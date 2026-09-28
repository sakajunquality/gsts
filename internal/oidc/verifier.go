// Package oidc verifies RS256 ID tokens using explicitly trusted discovery hosts.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
)

var ErrMalformed = errors.New("malformed JWT")

type UpstreamError struct{ Err error }

func (e *UpstreamError) Error() string { return "OIDC provider unavailable" }
func (e *UpstreamError) Unwrap() error { return e.Err }

type provider struct {
	keys                  map[string]*rsa.PublicKey
	expires, refreshAfter time.Time
	uri                   string
}
type Verifier struct {
	client    *http.Client
	mu        sync.Mutex
	providers map[string]*provider
}

func New(issuers []string) *Verifier {
	v := &Verifier{client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}, providers: map[string]*provider{}}
	for _, iss := range issuers {
		v.providers[iss] = &provider{}
	}
	return v
}

// Verify authenticates identity before policy lookup. Audience authorization is
// mandatory in policy.Evaluate, because a policy may override the default audience.
func (v *Verifier) Verify(ctx context.Context, raw string) (jwt.MapClaims, error) {
	if len(raw) > 16384 || len(strings.Split(raw, ".")) != 3 {
		return nil, ErrMalformed
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithJSONNumber())
	token, _, err := parser.ParseUnverified(raw, claims)
	if err != nil {
		return nil, ErrMalformed
	}
	if token.Method.Alg() != "RS256" {
		return nil, errors.New("unsupported algorithm")
	}
	iss, ok := claims["iss"].(string)
	if !ok {
		return nil, errors.New("issuer missing")
	}
	if _, ok = v.providers[iss]; !ok {
		return nil, errors.New("issuer not allowed")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" || len(kid) > 256 {
		return nil, errors.New("kid missing")
	}
	// jwt.MapClaims converts NumericDate through float64. Reject out-of-range
	// values first so conversion cannot wrap a future nbf into a past time.
	// This range (1970 through 9999) is also exactly representable in float64.
	for _, name := range []string{"iat", "exp", "nbf"} {
		value, exists := claims[name]
		if name == "nbf" && !exists {
			continue
		}
		n, ok := value.(json.Number)
		if !ok {
			return nil, errors.New("numeric timestamps required")
		}
		seconds, err := n.Int64()
		if err != nil || seconds < 0 || seconds > 253402300799 {
			return nil, errors.New("timestamps must be integer seconds between 1970 and 9999")
		}
	}
	iat, _ := claims.GetIssuedAt()
	exp, _ := claims.GetExpirationTime()
	sub, _ := claims["sub"].(string)
	aud, aerr := claims.GetAudience()
	if iat == nil || exp == nil || !exp.After(iat.Time) || sub == "" || aerr != nil || len(aud) == 0 {
		return nil, errors.New("required claims missing")
	}
	for _, a := range aud {
		if a == "" {
			return nil, errors.New("empty audience")
		}
	}
	key, err := v.key(ctx, iss, kid)
	if err != nil {
		return nil, err
	}
	if _, err = parser.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return key, nil }); err != nil {
		return nil, errors.New("signature or timestamps invalid")
	}
	return claims, nil
}

func allowedJWKS(iss, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	switch iss {
	case config.GoogleIssuer:
		return u.Host == "www.googleapis.com" || u.Host == "accounts.google.com"
	case config.ActionsIssuer:
		return u.Host == "token.actions.githubusercontent.com"
	}
	return false
}

func (v *Verifier) key(ctx context.Context, iss, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	p := v.providers[iss]
	now := time.Now()
	if k := p.keys[kid]; k != nil && now.Before(p.expires) {
		return k, nil
	}
	if p.keys[kid] == nil && now.Before(p.refreshAfter) {
		return nil, errors.New("unknown or expired signing key")
	}
	p.refreshAfter = now.Add(30 * time.Second)
	if p.uri == "" {
		var d struct {
			Issuer string `json:"issuer"`
			JWKS   string `json:"jwks_uri"`
		}
		if _, err := v.fetch(ctx, iss+"/.well-known/openid-configuration", &d); err != nil {
			return nil, &UpstreamError{err}
		}
		if d.Issuer != iss || !allowedJWKS(iss, d.JWKS) {
			return nil, &UpstreamError{errors.New("untrusted discovery")}
		}
		p.uri = d.JWKS
	}
	var set struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string }
	}
	ttl, err := v.fetch(ctx, p.uri, &set)
	if err != nil {
		return nil, &UpstreamError{err}
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") || (j.Alg != "" && j.Alg != "RS256") || j.Kid == "" {
			continue
		}
		n, e1 := base64.RawURLEncoding.DecodeString(j.N)
		e, e2 := base64.RawURLEncoding.DecodeString(j.E)
		if e1 != nil || e2 != nil || len(e) == 0 || len(e) > 4 || len(n) < 256 || len(n) > 1024 {
			continue
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		if exponent < 3 || exponent%2 == 0 || exponent > 2147483647 {
			continue
		}
		if _, exists := keys[j.Kid]; exists {
			return nil, &UpstreamError{errors.New("duplicate kid")}
		}
		keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent)}
	}
	if len(keys) == 0 {
		return nil, &UpstreamError{errors.New("empty JWKS")}
	}
	p.keys = keys
	p.expires = now.Add(ttl)
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}
func (v *Verifier) fetch(ctx context.Context, uri string, out any) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return 0, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("OIDC HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return 0, err
	}
	if len(b) > 1<<20 {
		return 0, errors.New("OIDC response too large")
	}
	if err = json.Unmarshal(b, out); err != nil {
		return 0, err
	}
	ttl := 5 * time.Minute
	for _, d := range strings.Split(resp.Header.Get("Cache-Control"), ",") {
		d = strings.TrimSpace(d)
		if d == "no-store" || d == "no-cache" {
			return 0, nil
		}
		if s, ok := strings.CutPrefix(d, "max-age="); ok {
			n, err := strconv.ParseInt(strings.Trim(s, `"`), 10, 64)
			if err == nil && n >= 0 && n <= 86400*365 {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	if age, err := strconv.ParseInt(resp.Header.Get("Age"), 10, 64); err == nil && age > 0 && age < 86400*365 {
		ttl -= time.Duration(age) * time.Second
	}
	if ttl < 0 {
		ttl = 0
	}
	return ttl, nil
}
