package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
)

func claims() jwt.MapClaims {
	return jwt.MapClaims{"iss": config.GoogleIssuer, "sub": "112233", "aud": "https://gsts.example.com", "email": "deploy@my-project.iam.gserviceaccount.com", "email_verified": true, "iat": json.Number("1000"), "exp": json.Number("9999999999")}
}
func TestGooglePolicy(t *testing.T) {
	source := `[google]
service_account = "deploy@my-project.iam.gserviceaccount.com"
[permissions]
contents = "read"
pull_requests = "write"
`
	p, err := Parse([]byte(source), false)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, key string
		value     any
		deny      bool
	}{
		{"valid", "sub", "123", false}, {"wrong issuer", "iss", config.ActionsIssuer, true}, {"wrong email", "email", "other@my-project.iam.gserviceaccount.com", true}, {"email case", "email", "Deploy@my-project.iam.gserviceaccount.com", true}, {"unverified", "email_verified", false, true}, {"string verified", "email_verified", "true", true}, {"wrong audience", "aud", "https://elsewhere", true}, {"multiple audiences", "aud", []any{"other", "https://gsts.example.com"}, false}, {"missing audience", "aud", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := claims()
			c[tc.key] = tc.value
			if err := p.Evaluate(c, "https://gsts.example.com"); (err != nil) != tc.deny {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
func TestPolicyConstraints(t *testing.T) {
	cases := []struct {
		name, source string
		org, invalid bool
	}{
		{"missing issuer", `subject="123"`, false, true},
		{"unknown field", `isssuer="x"`, false, true},
		{"google empty", `[google]`, false, true},
		{"google ambiguity", "[google]\nproject=\"my-project\"\nservice_account=\"x@y.iam.gserviceaccount.com\"", false, true},
		{"org repos under google", "[google]\nproject=\"my-project\"\nrepositories=[\"infra\"]", true, true},
		{"regex invalid", "issuer_pattern=\"[\"\nsubject=\"123\"", false, true},
		{"org permission", "issuer=\"i\"\nsubject=\"s\"\n[permissions]\nmembers=\"write\"", false, true},
		{"org permission allowed", "issuer=\"i\"\nsubject=\"s\"\n[permissions]\nmembers=\"write\"", true, false},
		{"empty repos", "issuer=\"i\"\nsubject=\"s\"\nrepositories=[]", true, true},
		{"repo repos", "issuer=\"i\"\nsubject=\"s\"\nrepositories=[\"infra\"]", false, true},
		{"invalid repo", "issuer=\"i\"\nsubject=\"s\"\nrepositories=[\"../infra\"]", true, true},
		{"negative lifetime", "issuer=\"i\"\nsubject=\"s\"\nmax_token_lifetime=-1", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.source
			if !strings.Contains(src, "[permissions]") {
				src += "\n[permissions]\ncontents=\"read\""
			}
			_, err := Parse([]byte(src), tc.org)
			if (err != nil) != tc.invalid {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
func TestANDAnchorsClaimsAndLifetime(t *testing.T) {
	p, err := Parse([]byte(`issuer_pattern = "https://accounts.google.com|https://other.example"
subject = "112233"
audience = "custom"
max_token_lifetime = 3600
claim_pattern = { email_verified = "true" }
[google]
project = "my-project"
[permissions]
contents = "read"
`), true)
	if err != nil {
		t.Fatal(err)
	}
	c := claims()
	c["aud"] = "custom"
	c["iat"] = json.Number("1000")
	c["exp"] = json.Number("4600")
	if err = p.Evaluate(c, "default"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"sub", "email", "email_verified", "exp"} {
		t.Run(key, func(t *testing.T) {
			copy := jwt.MapClaims{}
			for k, v := range c {
				copy[k] = v
			}
			switch key {
			case "sub":
				copy[key] = "other"
			case "email":
				copy[key] = "deploy@my-project.iam.gserviceaccount.com.evil"
			case "email_verified":
				delete(copy, key)
			case "exp":
				copy[key] = json.Number("4601")
			}
			if p.Evaluate(copy, "default") == nil {
				t.Fatal("accepted")
			}
		})
	}
	if matches("prefix-allowed", "", "allowed|other") {
		t.Fatal("regex not fully anchored")
	}
}
func TestNarrow(t *testing.T) {
	p := &Policy{Permissions: map[string]string{"contents": "read", "issues": "write"}, Repositories: []string{"infra", "api"}}
	tests := []struct {
		name        string
		permissions map[string]string
		repos       []string
		repo        string
		deny        bool
	}{
		{"defaults", nil, nil, "", false}, {"subset", map[string]string{"issues": "read"}, []string{"infra"}, "", false}, {"escalate", map[string]string{"contents": "write"}, nil, "", true}, {"unknown", map[string]string{"members": "read"}, nil, "", true}, {"empty permissions", map[string]string{}, nil, "", true}, {"invalid permission", map[string]string{"contents": "admin"}, nil, "", true}, {"empty repos", nil, []string{}, "", true}, {"outside repo", nil, []string{"other"}, "", true}, {"repo scoped", nil, nil, "infra", false}, {"repo narrowing", nil, []string{"infra"}, "infra", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, r, err := p.Narrow(tc.permissions, tc.repos, tc.repo)
			if (err != nil) != tc.deny {
				t.Fatalf("error=%v", err)
			}
			if tc.repo != "" && err == nil && (len(r) != 1 || r[0] != tc.repo) {
				t.Fatal(r)
			}
		})
	}
}
func TestExamples(t *testing.T) {
	paths, err := filepath.Glob("../../examples/policies/*.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(path, "trusted-issuers.toml") {
			if _, err = ParseTrust(b); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			continue
		}
		if _, err = Parse(b, strings.Contains(path, "org-")); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func claimPolicy(t *testing.T, extra string) *Policy {
	t.Helper()
	p, err := Parse([]byte("issuer = 'https://i'\nsubject = 's'\n"+extra+"\n[permissions]\ncontents = 'read'\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClaimExactMatch(t *testing.T) {
	base := func(k string, v any) jwt.MapClaims {
		c := jwt.MapClaims{"iss": "https://i", "sub": "s", "aud": "a"}
		if v != nil {
			c[k] = v
		}
		return c
	}
	tests := []struct {
		name   string
		policy string
		value  any
		deny   bool
	}{
		{"string ok", `claim = { x = "123" }`, "123", false},
		{"string mismatch", `claim = { x = "123" }`, "124", true},
		{"string prefix mismatch", `claim = { x = "123" }`, "1234", true},
		{"string policy vs number claim", `claim = { x = "123" }`, json.Number("123"), true},
		{"int ok", `claim = { x = 123 }`, json.Number("123"), false},
		{"int mismatch", `claim = { x = 123 }`, json.Number("124"), true},
		{"int vs float claim", `claim = { x = 123 }`, json.Number("123.5"), true},
		{"int vs float-form claim", `claim = { x = 123 }`, json.Number("123.0"), true},
		{"int vs string claim", `claim = { x = 123 }`, "123", true},
		{"bool true ok", `claim = { x = true }`, true, false},
		{"bool false ok", `claim = { x = false }`, false, false},
		{"bool mismatch", `claim = { x = true }`, false, true},
		{"bool vs string claim", `claim = { x = true }`, "true", true},
		{"missing claim", `claim = { x = "1" }`, nil, true},
		{"array claim", `claim = { x = "1" }`, []any{"1"}, true},
		{"object claim", `claim = { x = "1" }`, map[string]any{"a": "1"}, true},
		{"both exact and pattern ok", "claim = { x = \"123\" }\nclaim_pattern = { x = '12.' }", "123", false},
		{"exact ok pattern fails", "claim = { x = \"123\" }\nclaim_pattern = { x = '9.*' }", "123", true},
		{"pattern ok exact fails", "claim = { x = \"123\" }\nclaim_pattern = { x = '12.' }", "124", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := claimPolicy(t, tc.policy).Evaluate(base("x", tc.value), "a")
			if (err != nil) != tc.deny {
				t.Fatalf("error=%v", err)
			}
			if err != nil && strings.Contains(err.Error(), "123") {
				t.Fatalf("error leaks claim value: %v", err)
			}
		})
	}
}

func TestClaimAllEntriesRequired(t *testing.T) {
	p := claimPolicy(t, `claim = { a = "1", b = 2 }`)
	c := jwt.MapClaims{"iss": "https://i", "sub": "s", "aud": "a", "a": "1", "b": json.Number("2")}
	if err := p.Evaluate(c, "a"); err != nil {
		t.Fatal(err)
	}
	c["b"] = json.Number("3")
	if err := p.Evaluate(c, "a"); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestClaimParseValidation(t *testing.T) {
	for name, extra := range map[string]string{
		"float":        `claim = { x = 1.5 }`,
		"empty table":  `claim = {}`,
		"empty key":    `claim = { "" = "v" }`,
		"array":        `claim = { x = ["a"] }`,
		"nested table": "[claim.x]\ny = 'z'",
		"datetime":     `claim = { x = 2020-01-01T00:00:00Z }`,
	} {
		t.Run(name, func(t *testing.T) {
			src := "issuer = 'https://i'\nsubject = 's'\n"
			if strings.HasPrefix(extra, "[") {
				src += "[permissions]\ncontents = 'read'\n" + extra
			} else {
				src += extra + "\n[permissions]\ncontents = 'read'\n"
			}
			if _, err := Parse([]byte(src), false); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	_, err := Parse([]byte("issuer='i'\nsubject='s'\nclaim={x=1.5}\n[permissions]\ncontents='read'\n"), false)
	if err == nil || !strings.Contains(err.Error(), "claim values must be strings, integers or booleans") {
		t.Fatalf("error=%v", err)
	}
	claimPolicy(t, "[claim]\nx = 'a'\ny = 1\nz = true")
}
