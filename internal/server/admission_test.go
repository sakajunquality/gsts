package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
	"github.com/sakajunquality/gsts/internal/policy"
)

func TestAdmissionBoundsAndRefill(t *testing.T) {
	a := &admission{}
	c := config.Config{MaxConcurrent: 1, ExchangeRate: 60, ExchangeBurst: 2}
	now := time.Unix(100, 0)
	release, _ := a.acquire(c, now)
	if release == nil {
		t.Fatal("initial admission")
	}
	if r, retry := a.acquire(c, now); r != nil || retry != 1 {
		t.Fatal("concurrency bound")
	}
	release()
	release() // release is idempotent
	r, _ := a.acquire(c, now)
	if r == nil {
		t.Fatal("concurrency rejection consumed budget")
	}
	r()
	if r, retry := a.acquire(c, now); r != nil || retry != 1 {
		t.Fatal("burst bound")
	}
	r, _ = a.acquire(c, now.Add(time.Second))
	if r == nil {
		t.Fatal("refill")
	}
	r()
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if r, _ := a.acquire(c, now.Add(2*time.Second)); r != nil {
				r()
			}
		})
	}
	wg.Wait()
	if a.active != 0 || a.tokens < 0 {
		t.Fatal("admission leak")
	}
}

type verifierFunc func(context.Context, string) (jwt.MapClaims, error)

func (v verifierFunc) Verify(ctx context.Context, token string) (jwt.MapClaims, error) {
	return v(ctx, token)
}

type neverSigner struct{ t *testing.T }

func (n neverSigner) Token(context.Context) (string, error) {
	n.t.Error("unexpected signing")
	return "", errors.New("must not sign")
}

func TestAudienceDenialBeforeUpstream(t *testing.T) {
	s, g, _ := fixture()
	s.Signer = neverSigner{t}
	s.Verifier = verifierStub{aud: "https://other-service.example"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer signed-elsewhere")
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 || len(g.events) != 0 || !strings.Contains(w.Body.String(), "audience_not_allowed") {
		t.Fatal(w.Code, g.events, w.Body.String())
	}
}

func TestAudienceAllowlistIntersection(t *testing.T) {
	c := config.Config{Identifier: "service", AllowedAudiences: []string{"service", "custom"}}
	for _, audience := range []any{"custom", []any{"service", "other"}, []string{"service", "other"}} {
		original := jwt.MapClaims{"aud": audience}
		claims, ok := admittedClaims(original, c)
		if !ok {
			t.Fatal("explicit audience refused")
		}
		if err := (&policy.Policy{Audience: "other"}).Evaluate(claims, "service"); err == nil {
			t.Fatal("unlisted audience reached policy")
		}
	}
	for _, audience := range []any{"other", "", []any{""}, []any{"service", 123}, nil} {
		if _, ok := admittedClaims(jwt.MapClaims{"aud": audience}, c); ok {
			t.Fatal("invalid audience admitted", audience)
		}
	}
}

func TestLimitRejectsBeforeVerifierAndDoesNotBlockLiveness(t *testing.T) {
	s, _, _ := fixture()
	s.Config.ExchangeBurst = 1
	calls := 0
	s.Verifier = verifierFunc(func(context.Context, string) (jwt.MapClaims, error) { calls++; return nil, errors.New("denied") })
	h := s.Handler()
	for _, want := range []int{401, 429} {
		r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal(w.Code)
		}
		if want == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("missing retry delay")
		}
	}
	if calls != 1 {
		t.Fatal("limit did remote work")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/live", nil))
	if w.Code != 200 {
		t.Fatal("liveness rate limited")
	}
}

func TestOutOfOrderAdmissionDoesNotRefillTwice(t *testing.T) {
	a := &admission{}
	c := config.Config{MaxConcurrent: 10, ExchangeRate: 60, ExchangeBurst: 1}
	start := time.Unix(100, 0)
	r, _ := a.acquire(c, start)
	r()
	r, _ = a.acquire(c, start.Add(time.Minute))
	r()
	if r, _ := a.acquire(c, start); r != nil {
		r()
		t.Fatal("past arrival admitted")
	}
	if r, _ := a.acquire(c, start.Add(time.Minute)); r != nil {
		r()
		t.Fatal("time counted twice")
	}
}
