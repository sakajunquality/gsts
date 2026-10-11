package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sakajunquality/gsts/internal/github"
)

type responseStatus struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *responseStatus) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	if code >= 200 {
		w.wroteHeader = true
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) observe(next http.Handler, w http.ResponseWriter, r *http.Request) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		write(w, 503, map[string]string{"error": "request unavailable", "reason": "upstream_error"})
		return
	}
	requestID := hex.EncodeToString(id[:])
	w.Header().Set("X-Request-ID", requestID)
	start := time.Now()
	status := &responseStatus{ResponseWriter: w, status: 200}
	defer func() {
		s.Log.Info("exchange_completed", "request_id", requestID, "status", status.status, "duration_ms", float64(time.Since(start).Microseconds())/1000)
	}()
	next.ServeHTTP(status, r)
}

func stage(log *slog.Logger, name string) func(error) {
	start := time.Now()
	return func(err error) {
		attrs := []any{"stage", name, "duration_ms", float64(time.Since(start).Microseconds()) / 1000, "ok", err == nil}
		var api *github.APIError
		if errors.As(err, &api) {
			attrs = append(attrs, "github_request_id", api.RequestID, "upstream_status", api.Status, "retry_after", api.RetryAfter)
		}
		log.Info("exchange_stage", attrs...)
	}
}
