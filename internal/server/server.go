// Package server implements the public token-exchange HTTP API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
	"github.com/sakajunquality/gsts/internal/github"
	"github.com/sakajunquality/gsts/internal/oidc"
	"github.com/sakajunquality/gsts/internal/policy"
)

type Verifier interface {
	Verify(context.Context, string) (jwt.MapClaims, error)
}
type AppSigner interface {
	Token(context.Context) (string, error)
}
type GitHub interface {
	Installation(context.Context, string, string) (int64, error)
	CreateToken(context.Context, int64, string, map[string]string, []string) (github.Token, error)
	Policy(context.Context, string, string, string, string) ([]byte, error)
	Revoke(context.Context, string) error
}
type Server struct {
	readiness      readinessState
	Config         config.Config
	Verifier       Verifier
	Signer         AppSigner
	GitHub         GitHub
	Log            *slog.Logger
	AppPermissions map[string]string
}
type request struct {
	Scope        string            `json:"scope"`
	Identity     string            `json:"identity"`
	Permissions  map[string]string `json:"permissions"`
	Repositories []string          `json:"repositories"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", s.live)
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("POST /token", s.exchange)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) deny(w http.ResponseWriter, log *slog.Logger, status int, reason string, err error) {
	log.Warn("exchange_denied", "reason", reason, "detail", err)
	messages := map[string]string{"invalid_request": "invalid request", "invalid_token": "invalid ID token", "policy_mismatch": "access denied", "scope_not_allowed": "scope not allowed", "not_found": "policy or installation not found", "rate_limited": "upstream rate limit", "upstream_error": "upstream service unavailable", "invalid_policy": "invalid trust policy"}
	write(w, status, map[string]string{"error": messages[reason], "reason": reason})
}
func (s *Server) upstream(w http.ResponseWriter, log *slog.Logger, err error) {
	var e *github.APIError
	if errors.As(err, &e) {
		if e.RateLimited {
			s.deny(w, log, 429, "rate_limited", err)
			return
		}
		if e.Status == 404 {
			s.deny(w, log, 404, "not_found", err)
			return
		}
	}
	s.deny(w, log, 502, "upstream_error", err)
}
func (s *Server) revoke(token string) error {
	// Cleanup must survive cancellation/disconnection of the exchange request.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.GitHub.Revoke(ctx, token)
}
func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	log := s.Log
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var req request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.deny(w, log, 400, "invalid_request", errors.New("invalid JSON"))
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		s.deny(w, log, 400, "invalid_request", errors.New("trailing JSON"))
		return
	}
	parts := strings.Split(req.Scope, "/")
	if len(parts) > 2 || !config.ValidName(parts[0]) || (len(parts) == 2 && !config.ValidName(parts[1])) || !config.ValidName(req.Identity) || req.Identity == ".github" || len(req.Repositories) > 500 {
		s.deny(w, log, 400, "invalid_request", errors.New("invalid scope or identity"))
		return
	}
	owner, repo := parts[0], ""
	if len(parts) == 2 {
		repo = parts[1]
	}
	log = log.With("scope", req.Scope, "identity", req.Identity)
	if len(s.Config.AllowedOrgs) > 0 && !slices.ContainsFunc(s.Config.AllowedOrgs, func(o string) bool { return strings.EqualFold(o, owner) }) {
		s.deny(w, log, 403, "scope_not_allowed", errors.New("organization not allowed"))
		return
	}
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) != 1 || len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") {
		s.deny(w, log, 400, "invalid_request", errors.New("expected Bearer token"))
		return
	}
	claims, err := s.Verifier.Verify(ctx, auth[1])
	if err != nil {
		var providerErr *oidc.UpstreamError
		switch {
		case errors.Is(err, oidc.ErrMalformed):
			s.deny(w, log, 400, "invalid_request", err)
		case errors.As(err, &providerErr):
			s.upstream(w, log, err)
		default:
			s.deny(w, log, 401, "invalid_token", err)
		}
		return
	}
	email, _ := claims["email"].(string)
	log = log.With("email", email, "subject", claims["sub"], "issuer", claims["iss"])
	appJWT, err := s.Signer.Token(ctx)
	if err != nil {
		s.upstream(w, log, err)
		return
	}
	id, err := s.GitHub.Installation(ctx, owner, appJWT)
	if err != nil {
		s.upstream(w, log, err)
		return
	}
	policyRepo := repo
	if repo == "" {
		policyRepo = s.Config.OrgPolicyRepo
	}
	readToken, err := s.GitHub.CreateToken(ctx, id, appJWT, map[string]string{"contents": "read"}, []string{policyRepo})
	if err != nil {
		s.upstream(w, log, err)
		return
	}
	data, fetchErr := s.GitHub.Policy(ctx, owner, policyRepo, s.Config.PolicyPrefix+"/"+req.Identity+s.Config.PolicyExtension, readToken.Token)
	// Revoke before minting the caller's token: cleanup failure cannot orphan a
	// privileged token that was never delivered to its caller.
	if err = s.revoke(readToken.Token); err != nil {
		s.upstream(w, log, err)
		return
	}
	if fetchErr != nil {
		s.upstream(w, log, fetchErr)
		return
	}
	p, err := policy.Parse(data, repo == "")
	if err != nil {
		s.deny(w, log, 403, "invalid_policy", err)
		return
	}
	if err = p.Evaluate(claims, s.Config.Identifier); err != nil {
		s.deny(w, log, 403, "policy_mismatch", err)
		return
	}
	perms, repos, err := p.Narrow(req.Permissions, req.Repositories, repo)
	if err != nil {
		s.deny(w, log, 403, "policy_mismatch", err)
		return
	}
	for name, level := range p.Permissions {
		if s.AppPermissions != nil {
			max, ok := s.AppPermissions[name]
			if !ok || (max == "read" && level == "write") {
				log.Warn("policy_exceeds_app_permissions", "permission", name)
			}
		}
	}
	log.Info("exchange_authorized", "installation_id", id, "permissions", perms)
	token, err := s.GitHub.CreateToken(ctx, id, appJWT, perms, repos)
	if err != nil {
		s.upstream(w, log, err)
		return
	}
	// Return the effective permissions from GitHub (includes implicit metadata).
	log.Info("exchange_success", "installation_id", id, "permissions", token.Permissions)
	write(w, 200, token)
}
