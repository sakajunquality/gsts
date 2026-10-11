package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sakajunquality/gsts/internal/github"
)

func TestDiagnosticCorrelationAndPolicyFingerprint(t *testing.T) {
	s, g, logs := fixture()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer id-secret")
	r.Header.Set("X-Request-ID", "attacker-controlled")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	id := w.Header().Get("X-Request-ID")
	if len(id) != 32 || id == "attacker-controlled" || w.Code != 200 {
		t.Fatal(w.Code, id)
	}
	stages := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event["request_id"] != id {
			t.Fatal("uncorrelated log", event)
		}
		if event["msg"] == "exchange_stage" {
			stages[event["stage"].(string)] = true
			if event["duration_ms"].(float64) < 0 {
				t.Fatal("negative duration")
			}
		}
		if event["msg"] == "exchange_success" {
			if event["policy_sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(g.source))) || event["policy_repository"] != "org/repo" || event["policy_path"] != ".github/gsts/deploy.sts.toml" {
				t.Fatal(event)
			}
		}
	}
	for _, name := range []string{"verify_oidc", "sign_app_jwt", "find_installation", "create_policy_token", "fetch_policy", "revoke_policy_token", "parse_policy", "evaluate_policy", "create_caller_token"} {
		if !stages[name] {
			t.Fatal("missing timing", name)
		}
	}
}

func TestUpstreamRetryAndIDNoResponseLeak(t *testing.T) {
	s, g, logs := fixture()
	g.installationErr = &github.APIError{Status: 403, RateLimited: true, RetryAfter: "37", RequestID: "GH:123"}
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer id-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "37" {
		t.Fatal(w.Code, w.Header())
	}
	if !strings.Contains(logs.String(), `"github_request_id":"GH:123"`) || strings.Contains(w.Body.String(), "GH:123") {
		t.Fatal("invalid diagnostic boundary")
	}
	if len(g.events) != 1 {
		t.Fatal("upstream request retried")
	}
}
