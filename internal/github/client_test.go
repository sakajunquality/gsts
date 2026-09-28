package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
