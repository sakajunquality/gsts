package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
	"github.com/sakajunquality/gsts/internal/github"
	"github.com/sakajunquality/gsts/internal/oidc"
)

type verifierStub struct {
	err     error
	aud     string
	iss     string
	expired bool
}

func (v verifierStub) Verify(context.Context, string) (jwt.MapClaims, error) {
	aud := v.aud
	if aud == "" {
		aud = "https://gsts.example.com"
	}
	iss := v.iss
	if iss == "" {
		iss = config.GoogleIssuer
	}
	exp := time.Now().Add(time.Hour)
	if v.expired {
		exp = time.Now().Add(-time.Second)
	}
	return jwt.MapClaims{"iss": iss, "sub": "123", "email": "deploy@my-project.iam.gserviceaccount.com", "email_verified": true, "aud": aud, "exp": json.Number(strconv.FormatInt(exp.Unix(), 10))}, v.err
}

type signerStub struct{ err error }

func (s signerStub) Token(context.Context) (string, error) { return "app-jwt", s.err }

type githubStub struct {
	events                                        []string
	source                                        string
	fetchErr, revokeErr, installationErr, mintErr error
	cancel                                        context.CancelFunc
	perms                                         map[string]string
	repos                                         []string
	cleanupCanceled                               bool
	trustSource                                   string
	trustErr, readTokenErr                        error
	trustPath                                     string
	readRepos                                     []string
	policyFetches                                 []string
	headErr                                       error
	heads                                         []string
	refs                                          map[string]string
	mintHook                                      func()
}

func headSHA(repo string) string {
	if repo == ".github" {
		return strings.Repeat("b", 40)
	}
	return strings.Repeat("a", 40)
}

func (g *githubStub) Head(_ context.Context, owner, repo, _ string) (string, error) {
	g.events = append(g.events, "head")
	g.heads = append(g.heads, owner+"/"+repo)
	if g.headErr != nil {
		return "", g.headErr
	}
	return headSHA(repo), nil
}

func (g *githubStub) Installation(context.Context, string, string) (int64, error) {
	g.events = append(g.events, "installation")
	return 42, g.installationErr
}
func (g *githubStub) CreateToken(_ context.Context, _ int64, _ string, p map[string]string, r []string) (github.Token, error) {
	if len(g.events) == 1 {
		g.events = append(g.events, "read-token")
		if !reflect.DeepEqual(p, map[string]string{"contents": "read"}) || len(r) < 1 || len(r) > 2 {
			panic("unscoped read token")
		}
		g.readRepos = append([]string(nil), r...)
		if g.readTokenErr != nil {
			return github.Token{}, g.readTokenErr
		}
		return github.Token{Token: "read-secret"}, nil
	}
	g.events = append(g.events, "caller-token")
	if g.mintHook != nil {
		g.mintHook()
	}
	g.perms = p
	g.repos = r
	return github.Token{Token: "caller-secret", ExpiresAt: time.Now().Add(time.Hour), Permissions: p}, g.mintErr
}
func (g *githubStub) Policy(_ context.Context, owner, repo, path, ref, _ string) ([]byte, error) {
	g.policyFetches = append(g.policyFetches, owner+"/"+repo+"/"+path)
	if g.refs == nil {
		g.refs = map[string]string{}
	}
	g.refs[owner+"/"+repo+"/"+path] = ref
	if g.trustPath != "" && path == g.trustPath {
		g.events = append(g.events, "trust")
		return []byte(g.trustSource), g.trustErr
	}
	g.events = append(g.events, "policy")
	if g.cancel != nil {
		g.cancel()
	}
	return []byte(g.source), g.fetchErr
}
func (g *githubStub) Revoke(ctx context.Context, token string) error {
	g.cleanupCanceled = ctx.Err() != nil
	g.events = append(g.events, "revoke:"+token)
	return g.revokeErr
}
func fixture() (*Server, *githubStub, *bytes.Buffer) {
	g := &githubStub{source: `[google]
service_account="deploy@my-project.iam.gserviceaccount.com"
[permissions]
contents="read"
issues="write"
`}
	logs := new(bytes.Buffer)
	s := &Server{Config: config.Config{Identifier: "https://gsts.example.com", PolicyPrefix: ".github/gsts", PolicyExtension: ".sts.toml", OrgPolicyRepo: ".github"}, Verifier: verifierStub{}, Signer: signerStub{}, GitHub: g, Log: slog.New(slog.NewJSONHandler(logs, nil))}
	return s, g, logs
}
func TestExchange(t *testing.T) {
	s, g, logs := fixture()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy","permissions":{"contents":"read"}}`))
	r.Header.Set("Authorization", "Bearer id-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable response")
	}
	expected := []string{"installation", "read-token", "head", "policy", "revoke:read-secret", "caller-token"}
	if !reflect.DeepEqual(g.events, expected) {
		t.Fatal(g.events)
	}
	if !reflect.DeepEqual(g.repos, []string{"repo"}) || !reflect.DeepEqual(g.perms, map[string]string{"contents": "read"}) {
		t.Fatal("scope changed")
	}
	for _, secret := range []string{"id-secret", "read-secret", "caller-secret", "app-jwt"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("secret logged: %s", secret)
		}
	}
	for _, event := range []string{"exchange_authorized", "exchange_success"} {
		if !strings.Contains(logs.String(), event) {
			t.Fatal("missing audit event")
		}
	}
}
func TestExchangeFailures(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*Server, *githubStub)
		body    string
		status  int
		reason  string
		revoked bool
	}{
		{"signature", func(s *Server, g *githubStub) { s.Verifier = verifierStub{err: errors.New("bad signature")} }, "", 401, "invalid_token", false},
		{"malformed JWT", func(s *Server, g *githubStub) { s.Verifier = verifierStub{err: oidc.ErrMalformed} }, "", 400, "invalid_request", false},
		{"wrong audience", func(s *Server, g *githubStub) { s.Verifier = verifierStub{aud: "elsewhere"} }, "", 403, "audience_not_allowed", false},
		{"missing policy", func(s *Server, g *githubStub) { g.fetchErr = &github.APIError{Status: 404} }, "", 404, "not_found", true},
		{"fetch failure", func(s *Server, g *githubStub) { g.fetchErr = errors.New("upstream") }, "", 502, "upstream_error", true},
		{"revoke failure", func(s *Server, g *githubStub) { g.revokeErr = errors.New("failed revoke") }, "", 502, "upstream_error", true},
		{"rate limit", func(s *Server, g *githubStub) { g.installationErr = &github.APIError{Status: 403, RateLimited: true} }, "", 429, "rate_limited", false},
		{"org limit", func(s *Server, g *githubStub) { s.Config.AllowedOrgs = []string{"allowed"} }, "", 403, "scope_not_allowed", false},
		{"KMS failure", func(s *Server, g *githubStub) { s.Signer = signerStub{err: errors.New("KMS")} }, "", 502, "upstream_error", false},
		{"empty permissions", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy","permissions":{}}`, 403, "policy_mismatch", true},
		{"permission escalation", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy","permissions":{"contents":"write"}}`, 403, "policy_mismatch", true},
		{"path traversal", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"../deploy"}`, 400, "invalid_request", false},
		{"unknown field", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy","ref":"evil"}`, 400, "invalid_request", false},
		{"trailing JSON", func(*Server, *githubStub) {}, `{"scope":"org/repo","identity":"deploy"}{}`, 400, "invalid_request", false},
		{"bad policy", func(s *Server, g *githubStub) { g.source = "invalid TOML" }, "", 403, "invalid_policy", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, g, _ := fixture()
			tc.change(s, g)
			body := tc.body
			if body == "" {
				body = `{"scope":"org/repo","identity":"deploy"}`
			}
			r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer secret")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var res struct{ Reason string }
			_ = json.Unmarshal(w.Body.Bytes(), &res)
			if w.Code != tc.status || res.Reason != tc.reason {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			revoked := false
			for _, e := range g.events {
				if e == "caller-token" {
					t.Fatal("minted denied token")
				}
				if e == "revoke:read-secret" {
					revoked = true
				}
			}
			if revoked != tc.revoked {
				t.Fatal(g.events)
			}
		})
	}
}
func TestCanceledCleanup(t *testing.T) {
	s, g, _ := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.cancel = cancel
	g.fetchErr = context.Canceled
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer secret")
	s.Handler().ServeHTTP(httptest.NewRecorder(), r)
	if g.cleanupCanceled || g.events[len(g.events)-1] != "revoke:read-secret" {
		t.Fatal(g.events)
	}
}
func TestHealthAndMethods(t *testing.T) {
	s, _, _ := fixture()
	for _, path := range []string{"/live", "/healthz"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		want := 200
		if path == "/healthz" {
			want = 404
		}
		if w.Code != want {
			t.Fatal(path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/token", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

// Exercise real GitHub serialization and default-branch lookup through HTTP.
func TestHTTPGitHubFlow(t *testing.T) {
	s, _, _ := fixture()
	var calls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/orgs/org/installation":
			io.WriteString(w, `{"id":42,"account":{"login":"org","type":"Organization"}}`)
		case r.Method == "POST":
			var body struct {
				Permissions  map[string]string
				Repositories []string
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(body.Repositories, []string{"repo"}) {
				t.Error(body.Repositories)
			}
			_ = json.NewEncoder(w).Encode(github.Token{Token: "installation", ExpiresAt: time.Now().Add(time.Hour), Permissions: body.Permissions})
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.URL.Path == "/repos/org/repo/commits":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"sha": strings.Repeat("c", 40)}})
		default:
			if r.URL.RawQuery != "ref="+strings.Repeat("c", 40) {
				t.Error("unpinned read", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("[google]\nproject=\"my-project\"\n[permissions]\ncontents=\"read\""))})
		}
	}))
	defer upstream.Close()
	s.GitHub = github.New(upstream.URL)

	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if len(calls) != 6 || calls[2] != "GET /repos/org/repo/commits?per_page=1" || calls[3] != "GET /repos/org/repo/contents/.github/gsts/deploy.sts.toml?ref="+strings.Repeat("c", 40) || calls[4] != "DELETE /installation/token" {
		t.Fatal(calls)
	}
}

func exchangeOnce(s *Server, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestReplayedTokenRejected(t *testing.T) {
	s, g, logs := fixture()
	if w := exchangeOnce(s, "same-id-token"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	calls := len(g.events)
	w := exchangeOnce(s, "same-id-token")
	var res struct{ Reason string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 403 || res.Reason != "token_replayed" {
		t.Fatal(w.Code, w.Body)
	}
	if len(g.events) != calls {
		t.Fatal("replay reached GitHub", g.events)
	}
	if !strings.Contains(logs.String(), `"reason":"token_replayed"`) || strings.Contains(logs.String(), "same-id-token") {
		t.Fatal("bad replay audit log")
	}
	if w := exchangeOnce(s, "fresh-id-token"); w.Code != 200 {
		t.Fatal("fresh token rejected", w.Code, w.Body)
	}
}
func TestReplayProtectionOff(t *testing.T) {
	s, _, _ := fixture()
	s.Config.ReplayDisabled = true
	for i := 0; i < 2; i++ {
		if w := exchangeOnce(s, "same-id-token"); w.Code != 200 {
			t.Fatal(i, w.Code, w.Body)
		}
	}
}

func TestReplayIgnoresSignatureReencoding(t *testing.T) {
	// "AAA" and "AAB" decode to the same signature bytes; lenient base64url
	// verification accepts both, so both must map to one replay entry.
	s, g, _ := fixture()
	if w := exchangeOnce(s, "eyJ.eyJ.AAA"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	calls := len(g.events)
	w := exchangeOnce(s, "eyJ.eyJ.AAB")
	var res struct{ Reason string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 403 || res.Reason != "token_replayed" || len(g.events) != calls {
		t.Fatal(w.Code, w.Body, g.events)
	}
}
func TestReplayStoreFullRefusesWithoutEviction(t *testing.T) {
	s, g, _ := fixture()
	s.Config.ReplayMaxEntries = 1
	if w := exchangeOnce(s, "first"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	calls := len(g.events)
	w := exchangeOnce(s, "second")
	var res struct{ Reason string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 429 || res.Reason != "overloaded" || w.Header().Get("Retry-After") == "" || len(g.events) != calls {
		t.Fatal(w.Code, w.Body, w.Header(), g.events)
	}
	// The live entry was not evicted to make room.
	w = exchangeOnce(s, "first")
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 403 || res.Reason != "token_replayed" {
		t.Fatal(w.Code, w.Body)
	}
}
func TestReplayRejectsTokenExpiredBeforeConsumption(t *testing.T) {
	s, g, _ := fixture()
	s.Verifier = verifierStub{expired: true}
	w := exchangeOnce(s, "t")
	var res struct{ Reason string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 401 || res.Reason != "invalid_token" || slices.Contains(g.events, "caller-token") {
		t.Fatal(w.Code, w.Body, g.events)
	}
}

const trustPath = ".github/gsts/trusted-issuers.toml"

func trustFixture(src string, err error) (*Server, *githubStub) {
	s, g, _ := fixture()
	s.Config.OrgTrustFile = trustPath
	g.trustPath, g.trustSource, g.trustErr = trustPath, src, err
	return s, g
}
func reasonOf(w *httptest.ResponseRecorder) string {
	var res struct{ Reason string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	return res.Reason
}
func TestOrgTrustDisabledAddsNoCalls(t *testing.T) {
	s, g, _ := fixture()
	if w := exchangeOnce(s, "t"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !reflect.DeepEqual(g.policyFetches, []string{"org/repo/.github/gsts/deploy.sts.toml"}) || !reflect.DeepEqual(g.readRepos, []string{"repo"}) {
		t.Fatal(g.policyFetches, g.readRepos)
	}
	if !reflect.DeepEqual(g.events, []string{"installation", "read-token", "head", "policy", "revoke:read-secret", "caller-token"}) {
		t.Fatal(g.events)
	}
}
func TestOrgTrustAbsentAllows(t *testing.T) {
	s, g := trustFixture("", &github.APIError{Status: 404})
	if w := exchangeOnce(s, "t"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !reflect.DeepEqual(g.events, []string{"installation", "read-token", "head", "head", "trust", "policy", "revoke:read-secret", "caller-token"}) {
		t.Fatal(g.events)
	}
}
func TestOrgTrustReadTokenCoversBothRepositories(t *testing.T) {
	s, g := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
	w := exchangeOnce(s, "t")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !reflect.DeepEqual(g.readRepos, []string{"repo", ".github"}) {
		t.Fatal(g.readRepos)
	}
	if !reflect.DeepEqual(g.policyFetches, []string{"org/.github/" + trustPath, "org/repo/.github/gsts/deploy.sts.toml"}) {
		t.Fatal(g.policyFetches)
	}
}
func TestOrgTrustOrgScopeDoesNotDuplicateRepository(t *testing.T) {
	s, g := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
	g.source = "[google]\nservice_account=\"deploy@my-project.iam.gserviceaccount.com\"\n[permissions]\nmembers=\"read\"\n"
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer t")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !reflect.DeepEqual(g.readRepos, []string{".github"}) {
		t.Fatal(w.Code, w.Body, g.readRepos)
	}
}
func TestOrgTrustFailsClosedWhenOrgPolicyRepoInaccessible(t *testing.T) {
	// A 404/422 on the two-repository read token cannot prove the org has no
	// trust file, so there is no single-repository retry.
	for _, tc := range []struct {
		status, code int
		reason       string
	}{{404, 404, "not_found"}, {422, 502, "upstream_error"}} {
		s, g := trustFixture(`issuers = ["https://token.actions.githubusercontent.com"]`, nil)
		g.readTokenErr = &github.APIError{Status: tc.status}
		w := exchangeOnce(s, "t")
		var res struct{ Reason string }
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		if w.Code != tc.code || res.Reason != tc.reason {
			t.Fatal(tc.status, w.Code, w.Body)
		}
		if !reflect.DeepEqual(g.readRepos, []string{"repo", ".github"}) || len(g.policyFetches) != 0 || slices.Contains(g.events, "caller-token") {
			t.Fatal(g.readRepos, g.policyFetches, g.events)
		}
	}
}
func TestOrgTrustDecisions(t *testing.T) {
	actions := verifierStub{iss: config.ActionsIssuer}
	tests := []struct {
		name, src string
		verifier  Verifier
		err       error
		status    int
		reason    string
	}{
		{"only google, actions token", `issuers = ["https://accounts.google.com"]`, actions, nil, 403, "issuer_not_trusted"},
		{"lists actions issuer", `issuers = ["https://token.actions.githubusercontent.com"]`, actions, nil, 200, ""},
		{"pattern matches", `issuer_patterns = ['https://token\.actions\.githubusercontent\.com']`, actions, nil, 200, ""},
		{"pattern is anchored", `issuer_patterns = ['https://token\.actions']`, actions, nil, 403, "issuer_not_trusted"},
		{"invalid TOML", `issuers = [`, nil, nil, 403, "invalid_policy"},
		{"no lists", `issuers = []`, nil, nil, 403, "invalid_policy"},
		{"unknown key", "issuers = [\"https://accounts.google.com\"]\nextra = 1", nil, nil, 403, "invalid_policy"},
		{"empty file", ``, nil, nil, 403, "invalid_policy"},
		{"fetch 500", ``, nil, &github.APIError{Status: 500}, 502, "upstream_error"},
		{"fetch error", ``, nil, errors.New("boom"), 502, "upstream_error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, g := trustFixture(tc.src, tc.err)
			if tc.verifier != nil {
				s.Verifier = tc.verifier
				g.source = "issuer=\"https://token.actions.githubusercontent.com\"\nsubject=\"123\"\n[permissions]\ncontents=\"read\"\n"
			}
			w := exchangeOnce(s, "t")
			if w.Code != tc.status || reasonOf(w) != tc.reason {
				t.Fatal(w.Code, w.Body)
			}
			minted := slices.Contains(g.events, "caller-token")
			if minted != (tc.status == 200) {
				t.Fatal("caller token mismatch", g.events)
			}
			// The read token is always revoked before anything else is decided.
			if !slices.Contains(g.events, "revoke:read-secret") {
				t.Fatal("read token not revoked", g.events)
			}
			if tc.err != nil && slices.Contains(g.events, "policy") {
				t.Fatal("identity policy fetched after trust failure", g.events)
			}
		})
	}
}
func TestOrgTrustRevokeFailureStillFailsClosed(t *testing.T) {
	s, g := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
	g.revokeErr = errors.New("revoke")
	w := exchangeOnce(s, "t")
	if w.Code != 502 || slices.Contains(g.events, "caller-token") {
		t.Fatal(w.Code, g.events)
	}
}
func TestOrgTrustLogsFingerprint(t *testing.T) {
	s, _ := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
	logs := new(bytes.Buffer)
	s.Log = slog.New(slog.NewJSONHandler(logs, nil))
	exchangeOnce(s, "t")
	for _, want := range []string{"org_trust_sha256", `"org_trust_repository":"org/.github"`, trustPath} {
		if !strings.Contains(logs.String(), want) {
			t.Fatal("missing", want)
		}
	}
}

// failingWriter simulates a client that disconnected before the response.
type failingWriter struct{ http.ResponseWriter }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestHeadPinsReads(t *testing.T) {
	s, g := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
	logs := new(bytes.Buffer)
	s.Log = slog.New(slog.NewJSONHandler(logs, nil))
	if w := exchangeOnce(s, "t"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// Repository scope with trust: each repository pinned to its own head.
	if !reflect.DeepEqual(g.heads, []string{"org/repo", "org/.github"}) {
		t.Fatal(g.heads)
	}
	if g.refs["org/repo/.github/gsts/deploy.sts.toml"] != headSHA("repo") || g.refs["org/.github/"+trustPath] != headSHA(".github") || headSHA("repo") == headSHA(".github") {
		t.Fatal(g.refs)
	}
	for _, want := range []string{`"policy_commit":"` + headSHA("repo") + `"`, `"org_trust_commit":"` + headSHA(".github") + `"`, "resolve_head"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatal("missing", want)
		}
	}
}
func TestHeadSingleCallWithoutTrust(t *testing.T) {
	s, g, _ := fixture()
	if w := exchangeOnce(s, "t"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !reflect.DeepEqual(g.heads, []string{"org/repo"}) || g.refs["org/repo/.github/gsts/deploy.sts.toml"] != headSHA("repo") {
		t.Fatal(g.heads, g.refs)
	}
}
func TestHeadOrgScopeSharesOneCommit(t *testing.T) {
	s, g := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
	g.source = "[google]\nservice_account=\"deploy@my-project.iam.gserviceaccount.com\"\n[permissions]\nmembers=\"read\"\n"
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer t")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !reflect.DeepEqual(g.heads, []string{"org/.github"}) || len(g.refs) != 2 {
		t.Fatal(g.heads, g.refs)
	}
	for path, ref := range g.refs {
		if ref != headSHA(".github") {
			t.Fatal(path, ref)
		}
	}
}
func TestHeadFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		reason string
	}{{"not found", &github.APIError{Status: 404}, 404, "not_found"}, {"generic", errors.New("boom"), 502, "upstream_error"}} {
		t.Run(tc.name, func(t *testing.T) {
			s, g := trustFixture(`issuers = ["https://accounts.google.com"]`, nil)
			g.headErr = tc.err
			w := exchangeOnce(s, "t")
			if w.Code != tc.status || reasonOf(w) != tc.reason {
				t.Fatal(w.Code, w.Body)
			}
			if len(g.policyFetches) != 0 || slices.Contains(g.events, "caller-token") || !reflect.DeepEqual(g.events, []string{"installation", "read-token", "head", "revoke:read-secret"}) {
				t.Fatal(g.events, g.policyFetches)
			}
		})
	}
}
func TestUndeliveredCallerTokenRevoked(t *testing.T) {
	s, g, logs := fixture()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`))
	r.Header.Set("Authorization", "Bearer t")
	s.Handler().ServeHTTP(failingWriter{httptest.NewRecorder()}, r)
	if g.events[len(g.events)-1] != "revoke:caller-secret" {
		t.Fatal(g.events)
	}
	if !strings.Contains(logs.String(), "caller_token_revoked_undelivered") || strings.Contains(logs.String(), "exchange_success") || strings.Contains(logs.String(), "caller-secret") {
		t.Fatal(logs.String())
	}
}
func TestCanceledRequestRevokesCallerToken(t *testing.T) {
	s, g, _ := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"scope":"org/repo","identity":"deploy"}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer t")
	g.mintHook = cancel
	s.Handler().ServeHTTP(httptest.NewRecorder(), r)
	if g.events[len(g.events)-1] != "revoke:caller-secret" {
		t.Fatal(g.events)
	}
}
func TestDeliveredCallerTokenNotRevoked(t *testing.T) {
	s, g, logs := fixture()
	if w := exchangeOnce(s, "t"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if slices.Contains(g.events, "revoke:caller-secret") || !strings.Contains(logs.String(), "exchange_success") {
		t.Fatal(g.events)
	}
}
