package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRateLimitsAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		header, body string
		limited      bool
	}{
		{"primary", 403, "X-RateLimit-Remaining", `{"message":"API rate limit exceeded"}`, true}, {"secondary", 403, "", `{"message":"You have exceeded a secondary rate limit"}`, true}, {"429", 429, "", "", true}, {"permission", 403, "", `{"message":"Resource not accessible"}`, false}, {"missing", 404, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set(tc.header, "0")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			client := New(srv.URL)
			_, err := client.Installation(context.Background(), "org", "secret")
			var api *APIError
			if !errors.As(err, &api) || api.RateLimited != tc.limited || api.Status != tc.status {
				t.Fatal(err)
			}
		})
	}
}
func TestNoRedirectAndInstallationCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/orgs/redirect/installation" {
			http.Redirect(w, r, "/elsewhere", 302)
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"account":{"login":"org","type":"Organization"}}`))
	}))
	defer srv.Close()
	client := New(srv.URL)
	for _, org := range []string{"org", "ORG"} {
		if id, err := client.Installation(context.Background(), org, "secret"); err != nil || id != 1 {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("cache missed")
	}
	if _, err := client.Installation(context.Background(), "redirect", "secret"); err == nil {
		t.Fatal("redirect followed")
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestRetryAfterAndRequestID(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		header http.Header
		want   string
	}{
		{http.Header{"Retry-After": {"12"}}, "12"},
		{http.Header{"Retry-After": {"Sun, 11 Oct 2026 10:00:00 GMT"}}, "Sun, 11 Oct 2026 10:00:00 GMT"},
		{http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"1042"}}, "42"},
		{http.Header{"Retry-After": {"-1"}}, "60"},
		{http.Header{"Retry-After": {"invalid\r\nheader"}}, "60"},
	} {
		if got := retryAfter(tc.header, true, now); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "31")
		w.Header().Set("X-GitHub-Request-Id", "ABC:123")
		w.WriteHeader(429)
		w.Write([]byte(`{"token":"secret"}`))
	}))
	defer srv.Close()
	_, err := New(srv.URL).CreateToken(context.Background(), 1, "app-secret", map[string]string{"contents": "read"}, nil)
	var api *APIError
	if !errors.As(err, &api) || api.RetryAfter != "31" || api.RequestID != "ABC:123" || calls != 1 {
		t.Fatal(err, calls)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("secret retained")
	}
	if safeRequestID("bad\nvalue") != "" {
		t.Fatal("unsafe request ID")
	}
}

func TestRetryAfterBounds(t *testing.T) {
	now := time.Unix(1000, 0)
	if retryAfter(http.Header{"Retry-After": {"12"}}, false, now) != "" {
		t.Fatal("retry on non-rate response")
	}
	for _, reset := range []string{"-1", "9223372036854775807", "253402300800", "invalid"} {
		if got := retryAfter(http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {reset}}, true, now); got != "60" {
			t.Fatal(reset, got)
		}
	}
	if got := retryAfter(http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"999"}}, true, now); got != "1" {
		t.Fatal(got)
	}
}
