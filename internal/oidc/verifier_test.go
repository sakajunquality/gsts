package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func newFixture(t *testing.T) (*Verifier, *rsa.PrivateKey, *int) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := New([]string{config.GoogleIssuer, config.ActionsIssuer})
	calls := new(int)
	v.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		*calls++
		var body any
		if strings.HasSuffix(r.URL.Path, "openid-configuration") {
			uri := "https://www.googleapis.com/oauth2/v3/certs"
			if r.URL.Host == "token.actions.githubusercontent.com" {
				uri = config.ActionsIssuer + "/.well-known/jwks"
			}
			body = map[string]any{"issuer": "https://" + r.URL.Host, "jwks_uri": uri}
		} else {
			body = map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "key-1", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
		}
		b, _ := json.Marshal(body)
		return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": []string{"max-age=3600"}}, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
	})
	return v, key, calls
}
func validClaims() jwt.MapClaims {
	now := time.Now().Unix()
	return jwt.MapClaims{"iss": config.GoogleIssuer, "sub": "123", "aud": "https://gsts.example.com", "iat": now - 60, "exp": now + 3600}
}
func sign(t *testing.T, c jwt.MapClaims, key *rsa.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = "key-1"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestVerification(t *testing.T) {
	v, key, calls := newFixture(t)
	tests := []struct {
		name   string
		change func(jwt.MapClaims)
		deny   bool
	}{
		{"valid", func(jwt.MapClaims) {}, false},
		{"actions", func(c jwt.MapClaims) { c["iss"] = config.ActionsIssuer }, false},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, true},
		{"future iat", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Minute).Unix() }, true},
		{"future nbf", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Minute).Unix() }, true},
		{"overflow nbf", func(c jwt.MapClaims) { c["nbf"] = json.Number("1e100") }, true},
		{"negative iat", func(c jwt.MapClaims) { c["iat"] = json.Number("-9223372036854775808") }, true},
		{"overflow iat", func(c jwt.MapClaims) { c["iat"] = json.Number("9223372036854775807") }, true},
		{"overflow exp", func(c jwt.MapClaims) { c["exp"] = json.Number("9223372036854775807") }, true},
		{"null nbf", func(c jwt.MapClaims) { c["nbf"] = nil }, true},
		{"valid nbf", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(-time.Minute).Unix() }, false},
		{"missing iat", func(c jwt.MapClaims) { delete(c, "iat") }, true},
		{"missing exp", func(c jwt.MapClaims) { delete(c, "exp") }, true},
		{"missing sub", func(c jwt.MapClaims) { delete(c, "sub") }, true},
		{"empty aud", func(c jwt.MapClaims) { c["aud"] = "" }, true},
		{"empty aud member", func(c jwt.MapClaims) { c["aud"] = []string{"valid", ""} }, true},
		{"string exp", func(c jwt.MapClaims) { c["exp"] = "9999999999" }, true},
		{"untrusted issuer", func(c jwt.MapClaims) { c["iss"] = "http://169.254.169.254" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validClaims()
			tc.change(c)
			_, err := v.Verify(context.Background(), sign(t, c, key))
			if (err != nil) != tc.deny {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if *calls != 4 {
		t.Fatalf("cache failed: calls=%d", *calls)
	}
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(context.Background(), sign(t, validClaims(), wrong)); err == nil {
		t.Fatal("bad signature accepted")
	}
	for _, raw := range []string{"bad", "a.b.c", strings.Repeat("x", 20000)} {
		if _, err := v.Verify(context.Background(), raw); err != ErrMalformed {
			t.Fatalf("malformed: %v", err)
		}
	}
}
func TestSSRFAndDiscovery(t *testing.T) {
	for _, uri := range []string{"http://www.googleapis.com/keys", "https://www.googleapis.com.evil/keys", "https://www.googleapis.com:443/keys", "https://user@www.googleapis.com/keys", "https://169.254.169.254/keys", "https://token.actions.githubusercontent.com/keys"} {
		if allowedJWKS(config.GoogleIssuer, uri) {
			t.Fatal(uri)
		}
	}
	v, key, calls := newFixture(t)
	v.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		*calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"issuer":"https://evil.example","jwks_uri":"https://www.googleapis.com/keys"}`))}, nil
	})
	if _, err := v.Verify(context.Background(), sign(t, validClaims(), key)); err == nil {
		t.Fatal("mismatched discovery accepted")
	}
	if *calls != 1 {
		t.Fatal("followed untrusted discovery")
	}
}
func TestUnknownKidRefreshBound(t *testing.T) {
	v, key, calls := newFixture(t)
	raw := sign(t, validClaims(), key)
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims())
		token.Header["kid"] = fmt.Sprintf("attacker-%d", i)
		raw, _ := token.SignedString(key)
		if _, err := v.Verify(context.Background(), raw); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if *calls != 2 {
		t.Fatalf("unknown kid triggered fetch flood: %d", *calls)
	}
}
func TestCacheControl(t *testing.T) {
	v, _, _ := newFixture(t)
	v.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": []string{"public, max-age=90"}, "Age": []string{"30"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	var out any
	ttl, err := v.fetch(context.Background(), config.GoogleIssuer, &out)
	if err != nil || ttl != time.Minute {
		t.Fatalf("ttl=%v err=%v", ttl, err)
	}
}
