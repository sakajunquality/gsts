package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
	"github.com/sakajunquality/gsts/internal/github"
	"github.com/sakajunquality/gsts/internal/oidc"
)

type verifierStub struct {
	err error
	aud string
}

func (v verifierStub) Verify(context.Context, string) (jwt.MapClaims, error) {
	aud := v.aud
	if aud == "" {
		aud = "https://gsts.example.com"
	}
	return jwt.MapClaims{"iss": config.GoogleIssuer, "sub": "123", "email": "deploy@my-project.iam.gserviceaccount.com", "email_verified": true, "aud": aud}, v.err
}

type signerStub struct{ err error }

func (s signerStub) Token(context.Context) (string, error) { return "app-jwt", s.err }

type githubStub struct {
	events                                        []string
	source                                        string
	fetchErr, revokeErr, installationErr, mintErr error
	cancel                                        context.CancelFunc
	perms                                         map[string]string
	repos                                         []string
	cleanupCanceled                               bool
}

func (g *githubStub) Installation(context.Context, string, string) (int64, error) {
	g.events = append(g.events, "installation")
	return 42, g.installationErr
}
func (g *githubStub) CreateToken(_ context.Context, _ int64, _ string, p map[string]string, r []string) (github.Token, error) {
	if len(g.events) == 1 {
		g.events = append(g.events, "read-token")
		if !reflect.DeepEqual(p, map[string]string{"contents": "read"}) || len(r) != 1 {
			panic("unscoped read token")
		}
		return github.Token{Token: "read-secret"}, nil
	}
	g.events = append(g.events, "caller-token")
	g.perms = p
	g.repos = r
	return github.Token{Token: "caller-secret", ExpiresAt: time.Now().Add(time.Hour), Permissions: p}, g.mintErr
}
func (g *githubStub) Policy(context.Context, string, string, string, string) ([]byte, error) {
	g.events = append(g.events, "policy")
	if g.cancel != nil {
		g.cancel()
	}
	return []byte(g.source), g.fetchErr
}
func (g *githubStub) Revoke(ctx context.Context, token string) error {
	g.cleanupCanceled = ctx.Err() != nil
	g.events = append(g.events, "revoke:"+token)
	return g.revokeErr
}
func fixture() (*Server, *githubStub, *bytes.Buffer) {
	g := &githubStub{source: `[google]
service_account="deploy@my-project.iam.gserviceaccount.com"
[permissions]
contents="read"
issues="write"
`}
	logs := new(bytes.Buffer)
	s := &Server{Config: config.Config{Identifier: "https://gsts.example.com", PolicyPrefix: ".github/gsts", PolicyExtension: ".sts.toml", OrgPolicyRepo: ".github"}, Verifier: verifierStub{}, Signer: signerStub{}, GitHub: g, Log: slog.New(slog.NewJSONHandler(logs, nil))}
	return s, g, logs
}
func TestExchange(t *testing.T) {
	s, g, logs := fixture()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy","permissions":{"contents":"read"}}`))
	r.Header.Set("Authorization", "Bearer id-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable response")
	}
	expected := []string{"installation", "read-token", "policy", "revoke:read-secret", "caller-token"}
	if !reflect.DeepEqual(g.events, expected) {
		t.Fatal(g.events)
	}
	if !reflect.DeepEqual(g.repos, []string{"repo"}) || !reflect.DeepEqual(g.perms, map[string]string{"contents": "read"}) {
		t.Fatal("scope changed")
	}
	for _, secret := range []string{"id-secret", "read-secret", "caller-secret", "app-jwt"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("secret logged: %s", secret)
		}
	}
	for _, event := range []string{"exchange_authorized", "exchange_success"} {
		if !strings.Contains(logs.String(), event) {
			t.Fatal("missing audit event")
		}
	}
}
func TestExchangeFailures(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*Server, *githubStub)
		body    string
		status  int
		reason  string
		revoked bool
	}{
		{"signature", func(s *Server, g *githubStub) { s.Verifier = verifierStub{err: errors.New("bad signature")} }, "", 401, "invalid_token", false},
		{"malformed JWT", func(s *Server, g *githubStub) { s.Verifier = verifierStub{err: oidc.ErrMalformed} }, "", 400, "invalid_request", false},
		{"wrong audience", func(s *Server, g *githubStub) { s.Verifier = verifierStub{aud: "elsewhere"} }, "", 403, "policy_mismatch", true},
		{"missing policy", func(s *Server, g *githubStub) { g.fetchErr = &github.APIError{Status: 404} }, "", 404, "not_found", true},
		{"fetch failure", func(s *Server, g *githubStub) { g.fetchErr = errors.New("upstream") }, "", 502, "upstream_error", true},
		{"revoke failure", func(s *Server, g *githubStub) { g.revokeErr = errors.New("failed revoke") }, "", 502, "upstream_error", true},
		{"rate limit", func(s *Server, g *githubStub) { g.installationErr = &github.APIError{Status: 403, RateLimited: true} }, "", 429, "rate_limited", false},
		{"org limit", func(s *Server, g *githubStub) { s.Config.AllowedOrgs = []string{"allowed"} }, "", 403, "scope_not_allowed", false},
		{"KMS failure", func(s *Server, g *githubStub) { s.Signer = signerStub{err: errors.New("KMS")} }, "", 502, "upstream_error", false},
		{"empty permissions", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy","permissions":{}}`, 403, "policy_mismatch", true},
		{"permission escalation", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy","permissions":{"contents":"write"}}`, 403, "policy_mismatch", true},
		{"path traversal", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"../deploy"}`, 400, "invalid_request", false},
		{"unknown field", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy","ref":"evil"}`, 400, "invalid_request", false},
		{"trailing JSON", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy"}{}`, 400, "invalid_request", false},
		{"bad policy", func(s *Server, g *githubStub) { g.source = "invalid TOML" }, "", 403, "invalid_policy", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, g, _ := fixture()
			tc.change(s, g)
			body := tc.body
			if body == "" {
				body = `{"scope":"org/repo","identity":"deploy"}`
			}
			r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer secret")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var res struct{ Reason string }
			_ = json.Unmarshal(w.Body.Bytes(), &res)
			if w.Code != tc.status || res.Reason != tc.reason {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			revoked := false
			for _, e := range g.events {
				if e == "caller-token" {
					t.Fatal("minted denied token")
				}
				if e == "revoke:read-secret" {
					revoked = true
				}
			}
			if revoked != tc.revoked {
				t.Fatal(g.events)
			}
		})
	}
}
func TestCanceledCleanup(t *testing.T) {
	s, g, _ := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.cancel = cancel
	g.fetchErr = context.Canceled
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer secret")
	s.Handler().ServeHTTP(httptest.NewRecorder(), r)
	if g.cleanupCanceled || g.events[len(g.events)-1] != "revoke:read-secret" {
		t.Fatal(g.events)
	}
}
func TestHealthAndMethods(t *testing.T) {
	s, _, _ := fixture()
	for _, path := range []string{"/live", "/healthz"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		want := 200
		if path == "/healthz" {
			want = 404
		}
		if w.Code != want {
			t.Fatal(path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/token", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

// Exercise real GitHub serialization and default-branch lookup through HTTP.
func TestHTTPGitHubFlow(t *testing.T) {
	s, _, _ := fixture()
	var calls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/orgs/org/installation":
			io.WriteString(w, `{"id":42,"account":{"login":"org","type":"Organization"}}`)
		case r.Method == "POST":
			var body struct {
				Permissions  map[string]string
				Repositories []string
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(body.Repositories, []string{"repo"}) {
				t.Error(body.Repositories)
			}
			_ = json.NewEncoder(w).Encode(github.Token{Token: "installation", ExpiresAt: time.Now().Add(time.Hour), Permissions: body.Permissions})
		case r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			if r.URL.RawQuery != "" {
				t.Error("branch override")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("[google]\nproject=\"my-project\"\n[permissions]\ncontents=\"read\""))})
		}
	}))
	defer upstream.Close()
	s.GitHub = github.New(upstream.URL)

	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if len(calls) != 5 || calls[2] != "GET /repos/org/repo/contents/.github/gsts/deploy.sts.toml" || calls[3] != "DELETE /installation/token" {
		t.Fatal(calls)
	}
}
