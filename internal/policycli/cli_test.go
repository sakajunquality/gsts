package policycli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.toml")
	f := filepath.Join(dir, "fixtures.json")
	if err := os.WriteFile(p, []byte("issuer = 'issuer'\nsubject = 'subject'\nclaim_pattern = { run_number = '42' }\n[permissions]\ncontents = 'read'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, body string
		wantErr    bool
		contains   string
	}{
		{"matches and denies", `{"cases":[{"name":"allowed","expect":"allow","claims":{"iss":"issuer","sub":"subject","aud":["other","gsts"],"run_number":42}},{"name":"denied","expect":"deny","claims":{"iss":"issuer","sub":"other","aud":"gsts","run_number":42}}]}`, false, "PASS denied"},
		{"mismatch fails CI", `{"cases":[{"name":"unexpected","expect":"deny","claims":{"iss":"issuer","sub":"subject","aud":"gsts","run_number":42}}]}`, true, "FAIL unexpected"},
		{"malformed deny", `{"cases":[{"name":"bad","expect":"deny","claims":{"iss":3,"sub":"subject","aud":"gsts"}}]}`, true, ""},
		{"trailing JSON", `{"cases":[]} {}`, true, ""},
		{"unknown field", `{"cases":[],"casez":[]}`, true, ""},
		{"empty suite", `{"cases":[]}`, true, ""},
		{"bad timestamps", `{"cases":[{"name":"bad","expect":"deny","claims":{"iss":"issuer","sub":"subject","aud":"gsts","exp":"invalid"}}]}`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(f, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := Run([]string{"test", "--policy", p, "--identifier", "gsts", "--fixtures", f}, &out, &out)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error %v; output %s", err, out.String())
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Fatal(out.String())
			}
			if tc.wantErr && tc.contains == "" && strings.Contains(out.String(), "PASS") {
				t.Fatal("invalid fixture evaluated")
			}
		})
	}
}

func TestValidateScope(t *testing.T) {
	p := filepath.Join(t.TempDir(), "org.toml")
	if err := os.WriteFile(p, []byte("issuer='issuer'\nsubject='subject'\n[permissions]\nmembers='read'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run([]string{"validate", "--policy", p}, &out, &out); err == nil {
		t.Fatal("repository policy accepted members permission")
	}
	if err := Run([]string{"validate", "--policy", p, "--org"}, &out, &out); err != nil {
		t.Fatal(err)
	}
}

func TestRejectMalformedSuites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.toml")
	f := filepath.Join(dir, "fixtures.json")
	if err := os.WriteFile(p, []byte("issuer='issuer'\nsubject='subject'\n[permissions]\ncontents='read'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"duplicate names":      `{"cases":[{"name":"same","expect":"deny","claims":{"iss":"issuer","sub":"subject","aud":"other"}},{"name":"same","expect":"deny","claims":{"iss":"issuer","sub":"subject","aud":"other"}}]}`,
		"bad audience element": `{"cases":[{"name":"bad","expect":"deny","claims":{"iss":"issuer","sub":"subject","aud":["gsts",42]}}]}`,
		"inverted lifetime":    `{"cases":[{"name":"bad","expect":"deny","claims":{"iss":"issuer","sub":"subject","aud":"gsts","iat":200,"exp":100}}]}`,
		"unknown case field":   `{"cases":[{"name":"bad","expect":"deny","claimz":{},"claims":{"iss":"issuer","sub":"subject","aud":"gsts"}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(f, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := Run([]string{"test", "--policy", p, "--identifier", "gsts", "--fixtures", f}, &out, &out)
			if err == nil {
				t.Fatal("malformed suite accepted")
			}
			if strings.Contains(out.String(), "PASS") {
				t.Fatal("malformed suite evaluated")
			}
		})
	}
}

func TestTrustedWorkflowExample(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"test", "--policy", "../../examples/policy-tests/trusted-workflow.sts.toml", "--identifier", "https://gsts.example.com", "--fixtures", "../../examples/policy-tests/trusted-workflow.json"}, &out, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
}
