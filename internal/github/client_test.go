package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

func TestHeadAndPolicyRef(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 3)[:40]
	var uris []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uris = append(uris, r.URL.EscapedPath()+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer read-secret" {
			t.Error("missing token")
		}
		if strings.HasSuffix(r.URL.Path, "/commits") {
			switch r.URL.Path {
			case "/repos/org/bad/commits":
				_, _ = w.Write([]byte(`[{"sha":"ABCDEF"}]`))
			case "/repos/org/upper/commits":
				_, _ = w.Write([]byte(`[{"sha":"` + strings.ToUpper(sha) + `"}]`))
			case "/repos/org/missing/commits":
				w.WriteHeader(404)
			case "/repos/org/redirect/commits":
				http.Redirect(w, r, "/elsewhere", 302)
			default:
				_, _ = w.Write([]byte(`[{"sha":"` + sha + `"}]`))
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "base64", "size": 2, "content": base64.StdEncoding.EncodeToString([]byte("ok"))})
	}))
	defer srv.Close()
	c := New(srv.URL)
	got, err := c.Head(context.Background(), "org", "repo", "read-secret")
	if err != nil || got != sha {
		t.Fatal(got, err)
	}
	for _, repo := range []string{"bad", "upper", "redirect"} {
		if _, err := c.Head(context.Background(), "org", repo, "read-secret"); err == nil {
			t.Fatal("accepted", repo)
		}
	}
	if _, err := c.Head(context.Background(), "org", "missing", "read-secret"); !IsNotFound(err) {
		t.Fatal(err)
	}
	if b, err := c.Policy(context.Background(), "org", "repo", ".github/gsts/a.toml", sha, "read-secret"); err != nil || string(b) != "ok" {
		t.Fatal(b, err)
	}
	if _, err := c.Policy(context.Background(), "org", "repo", "p.toml", "a&b=c d", "read-secret"); err != nil {
		t.Fatal(err)
	}
	if uris[0] != "/repos/org/repo/commits?per_page=1" || uris[len(uris)-2] != "/repos/org/repo/contents/.github/gsts/a.toml?ref="+sha || uris[len(uris)-1] != "/repos/org/repo/contents/p.toml?ref=a%26b%3Dc+d" {
		t.Fatal(uris)
	}
}
