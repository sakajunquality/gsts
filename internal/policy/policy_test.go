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
		if _, err = Parse(b, strings.Contains(path, "org-")); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
