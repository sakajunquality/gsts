package config

import "testing"

func TestConfigSecurity(t *testing.T) {
	t.Setenv("GSTS_GITHUB_APP_ID", "123")
	t.Setenv("GSTS_IDENTIFIER", "https://gsts.example.com")
	t.Setenv("GSTS_KEY_SOURCE", "kms")
	t.Setenv("GSTS_KMS_KEY", "projects/p/locations/r/keyRings/k/cryptoKeys/k/cryptoKeyVersions/1")
	for _, k := range []string{"GSTS_ALLOWED_AUDIENCES", "GSTS_MAX_CONCURRENT_EXCHANGES", "GSTS_EXCHANGE_RATE_PER_MINUTE", "GSTS_EXCHANGE_BURST", "GSTS_REPLAY_MAX_ENTRIES", "GSTS_REPLAY_PROTECTION", "GSTS_ALLOWED_ISSUERS", "GSTS_ALLOWED_ORGS", "GSTS_POLICY_PATH_PREFIX", "GSTS_POLICY_FILE_EXTENSION", "GSTS_ORG_POLICY_REPO", "GSTS_ORG_TRUST_FILE", "GSTS_GITHUB_API_URL", "GSTS_LOG_FORMAT", "PORT"} {
		t.Setenv(k, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ReplayMaxEntries != 100000 || c.ReplayDisabled {
		t.Fatal("unexpected replay defaults", c.ReplayMaxEntries, c.ReplayDisabled)
	}
	if c.OrgTrustFile != "" {
		t.Fatal("org trust must be disabled by default")
	}
	for _, tc := range []struct{ name, key, value string }{
		{"empty audiences", "GSTS_ALLOWED_AUDIENCES", ", ,"}, {"zero concurrency", "GSTS_MAX_CONCURRENT_EXCHANGES", "0"}, {"negative rate", "GSTS_EXCHANGE_RATE_PER_MINUTE", "-1"}, {"invalid burst", "GSTS_EXCHANGE_BURST", "NaN"}, {"excessive burst", "GSTS_EXCHANGE_BURST", "1000001"},
		{"zero replay entries", "GSTS_REPLAY_MAX_ENTRIES", "0"}, {"excessive replay entries", "GSTS_REPLAY_MAX_ENTRIES", "10000001"}, {"invalid replay entries", "GSTS_REPLAY_MAX_ENTRIES", "many"}, {"invalid replay protection", "GSTS_REPLAY_PROTECTION", "maybe"}, {"uppercase replay protection", "GSTS_REPLAY_PROTECTION", "OFF"},
		{"insecure key", "GSTS_KEY_SOURCE", "file"}, {"key without version", "GSTS_KMS_KEY", "projects/p/locations/r/keyRings/k/cryptoKeys/k"}, {"SSRF issuer", "GSTS_ALLOWED_ISSUERS", "http://169.254.169.254"}, {"insecure GitHub", "GSTS_GITHUB_API_URL", "http://github.example"}, {"bad identifier", "GSTS_IDENTIFIER", "http://production.example"}, {"bad port", "PORT", "0"}, {"path traversal", "GSTS_POLICY_PATH_PREFIX", "../policies"},
		{"absolute trust file", "GSTS_ORG_TRUST_FILE", "/trusted.toml"}, {"trust file traversal", "GSTS_ORG_TRUST_FILE", "../trusted.toml"}, {"trust file uncleaned", "GSTS_ORG_TRUST_FILE", ".github//trusted.toml"}, {"trust file query", "GSTS_ORG_TRUST_FILE", "trusted.toml?ref=evil"}, {"trust file fragment", "GSTS_ORG_TRUST_FILE", "trusted.toml#x"}, {"trust file backslash", "GSTS_ORG_TRUST_FILE", `a\b.toml`}, {"trust file dot", "GSTS_ORG_TRUST_FILE", "."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GSTS_ALLOW_INSECURE_KEY", "")
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestReplaySettings(t *testing.T) {
	t.Setenv("GSTS_GITHUB_APP_ID", "123")
	t.Setenv("GSTS_IDENTIFIER", "https://gsts.example.com")
	t.Setenv("GSTS_KEY_SOURCE", "kms")
	t.Setenv("GSTS_KMS_KEY", "projects/p/locations/r/keyRings/k/cryptoKeys/k/cryptoKeyVersions/1")
	t.Setenv("GSTS_REPLAY_PROTECTION", "off")
	t.Setenv("GSTS_REPLAY_MAX_ENTRIES", "10000000")
	c, err := Load()
	if err != nil || !c.ReplayDisabled || c.ReplayMaxEntries != 10000000 {
		t.Fatal(err, c.ReplayDisabled, c.ReplayMaxEntries)
	}
}

func TestOrgTrustFileSetting(t *testing.T) {
	t.Setenv("GSTS_GITHUB_APP_ID", "123")
	t.Setenv("GSTS_IDENTIFIER", "https://gsts.example.com")
	t.Setenv("GSTS_KEY_SOURCE", "kms")
	t.Setenv("GSTS_KMS_KEY", "projects/p/locations/r/keyRings/k/cryptoKeys/k/cryptoKeyVersions/1")
	t.Setenv("GSTS_ORG_TRUST_FILE", ".github/gsts/trusted-issuers.toml")
	c, err := Load()
	if err != nil || c.OrgTrustFile != ".github/gsts/trusted-issuers.toml" {
		t.Fatal(err, c.OrgTrustFile)
	}
}
