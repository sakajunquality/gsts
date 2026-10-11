package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type healthSigner struct {
	calls   atomic.Int64
	fail    atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *healthSigner) Token(context.Context) (string, error) { return "cached", nil }
func (s *healthSigner) FreshToken(ctx context.Context) (string, error) {
	s.calls.Add(1)
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if s.fail.Load() {
		return "", errors.New("private KMS detail")
	}
	return "fresh", nil
}

type healthGitHub struct {
	GitHub
	calls atomic.Int64
	fail  atomic.Bool
}

func (g *healthGitHub) AppPermissions(_ context.Context, token string) (map[string]string, error) {
	g.calls.Add(1)
	if token != "fresh" {
		return nil, errors.New("cached token used")
	}
	if g.fail.Load() {
		return nil, errors.New("invalid GitHub App credential")
	}
	return nil, nil
}
func TestReadinessFreshChecksAndExpiry(t *testing.T) {
	signer := &healthSigner{}
	github := &healthGitHub{}
	s := &Server{Signer: signer, GitHub: github}
	if !s.readinessResult(context.Background()) {
		t.Fatal("initial check failed")
	}
	signer.fail.Store(true)
	if !s.readinessResult(context.Background()) || signer.calls.Load() != 1 {
		t.Fatal("result should remain cached within TTL")
	}
	s.readiness.mu.Lock()
	s.readiness.expires = time.Now().Add(-time.Second)
	s.readiness.mu.Unlock()
	if s.readinessResult(context.Background()) || signer.calls.Load() != 2 {
		t.Fatal("fresh check must detect KMS failure after TTL")
	}
	signer.fail.Store(false)
	github.fail.Store(true)
	s.readiness.mu.Lock()
	s.readiness.expires = time.Now().Add(-time.Second)
	s.readiness.mu.Unlock()
	if s.readinessResult(context.Background()) {
		t.Fatal("GitHub rejection must fail readiness")
	}
	if s.readinessResult(context.Background()) || signer.calls.Load() != 3 {
		t.Fatal("failure must also be cached to limit upstream calls")
	}
}
func TestReadinessCoalescesAndCancellation(t *testing.T) {
	signer := &healthSigner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s := &Server{Signer: signer, GitHub: &healthGitHub{}}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan bool, 1)
	go func() { first <- s.readinessResult(ctx) }()
	<-signer.entered
	cancel()
	if <-first {
		t.Fatal("canceled caller should fail")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if !s.readinessResult(context.Background()) {
				t.Error("shared check failed")
			}
		})
	}
	close(signer.release)
	wg.Wait()
	if signer.calls.Load() != 1 {
		t.Fatal("concurrent probes duplicated signing")
	}
}
func TestLivenessIndependentAndReadyErrorsPrivate(t *testing.T) {
	signer := &healthSigner{}
	signer.fail.Store(true)
	s := &Server{Signer: signer, GitHub: &healthGitHub{}}
	live := httptest.NewRecorder()
	s.live(live, httptest.NewRequest("GET", "/live", nil))
	if live.Code != 200 || signer.calls.Load() != 0 {
		t.Fatal("liveness accessed dependency")
	}
	ready := httptest.NewRecorder()
	s.ready(ready, httptest.NewRequest("GET", "/ready", nil))
	if ready.Code != 503 || ready.Body.String() != "{\"ok\":false}\n" {
		t.Fatal("readiness exposed error or wrong status", ready.Body.String())
	}
}
