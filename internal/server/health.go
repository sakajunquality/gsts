package server

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const readinessTTL = 10 * time.Second
const readinessTimeout = 5 * time.Second

type freshAppSigner interface {
	FreshToken(context.Context) (string, error)
}
type appChecker interface {
	AppPermissions(context.Context, string) (map[string]string, error)
}

type readinessState struct {
	mu      sync.Mutex
	expires time.Time
	ok      bool
	running chan struct{}
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ok := s.readinessResult(r.Context())
	status := http.StatusServiceUnavailable
	if ok {
		status = http.StatusOK
	}
	write(w, status, map[string]bool{"ok": ok})
}

func (s *Server) readinessResult(ctx context.Context) bool {
	state := &s.readiness
	state.mu.Lock()
	if time.Now().Before(state.expires) {
		ok := state.ok
		state.mu.Unlock()
		return ok
	}
	done := state.running
	if done == nil {
		done = make(chan struct{})
		state.running = done
		// A disconnected probe must not cancel the shared check for other callers.
		go func() {
			checkCtx, cancel := context.WithTimeout(context.Background(), readinessTimeout)
			defer cancel()
			ok := s.checkReadiness(checkCtx)
			state.mu.Lock()
			state.ok = ok
			state.expires = time.Now().Add(readinessTTL)
			state.running = nil
			close(done)
			state.mu.Unlock()
		}()
	}
	state.mu.Unlock()
	select {
	case <-ctx.Done():
		return false
	case <-done:
		state.mu.Lock()
		ok := state.ok
		state.mu.Unlock()
		return ok
	}
}

func (s *Server) checkReadiness(ctx context.Context) bool {
	signer, ok := s.Signer.(freshAppSigner)
	if !ok {
		return false
	}
	client, ok := s.GitHub.(appChecker)
	if !ok {
		return false
	}
	token, err := signer.FreshToken(ctx)
	if err != nil {
		return false
	}
	_, err = client.AppPermissions(ctx, token)
	return err == nil
}
