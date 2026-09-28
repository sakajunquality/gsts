package config

import "testing"

func TestConfigSecurity(t *testing.T) {
	t.Setenv("GSTS_GITHUB_APP_ID", "123")
	t.Setenv("GSTS_IDENTIFIER", "https://gsts.example.com")
	t.Setenv("GSTS_KEY_SOURCE", "kms")
	t.Setenv("GSTS_KMS_KEY", "projects/p/locations/r/keyRings/k/cryptoKeys/k/cryptoKeyVersions/1")
	for _, k := range []string{"GSTS_ALLOWED_ISSUERS", "GSTS_ALLOWED_ORGS", "GSTS_POLICY_PATH_PREFIX", "GSTS_POLICY_FILE_EXTENSION", "GSTS_ORG_POLICY_REPO", "GSTS_GITHUB_API_URL", "GSTS_LOG_FORMAT", "PORT"} {
		t.Setenv(k, "")
	}
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, key, value string }{
		{"insecure key", "GSTS_KEY_SOURCE", "file"}, {"key without version", "GSTS_KMS_KEY", "projects/p/locations/r/keyRings/k/cryptoKeys/k"}, {"SSRF issuer", "GSTS_ALLOWED_ISSUERS", "http://169.254.169.254"}, {"insecure GitHub", "GSTS_GITHUB_API_URL", "http://github.example"}, {"bad identifier", "GSTS_IDENTIFIER", "http://production.example"}, {"bad port", "PORT", "0"}, {"path traversal", "GSTS_POLICY_PATH_PREFIX", "../policies"},
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
