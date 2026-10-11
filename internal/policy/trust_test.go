package policy

import "testing"

func TestParseTrustInvalid(t *testing.T) {
	for name, src := range map[string]string{
		"empty file":    ``,
		"empty list":    `issuers = []`,
		"both empty":    "issuers = []\nissuer_patterns = []",
		"unknown key":   "issuers = [\"a\"]\nissuer_pattern = \"b\"",
		"bad regex":     `issuer_patterns = ['(']`,
		"empty issuer":  `issuers = [""]`,
		"empty pattern": `issuer_patterns = [""]`,
		"not toml":      `issuers = `,
		"wrong type":    `issuers = "https://accounts.google.com"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTrust([]byte(src)); err == nil {
				t.Fatal("accepted invalid trust file")
			}
		})
	}
}

func TestTrustAllows(t *testing.T) {
	tf, err := ParseTrust([]byte("issuers = [\"https://accounts.google.com\"]\nissuer_patterns = ['https://token\\.actions\\.githubusercontent\\.com']"))
	if err != nil {
		t.Fatal(err)
	}
	for issuer, want := range map[string]bool{
		"https://accounts.google.com":                      true,
		"https://accounts.google.com/":                     false,
		"https://token.actions.githubusercontent.com":      true,
		"https://token.actions.githubusercontent.com/evil": false,
		"evil-https://token.actions.githubusercontent.com": false,
		"https://tokenXactions.githubusercontent.com":      false,
		"": false,
	} {
		if got := tf.Allows(issuer); got != want {
			t.Errorf("Allows(%q)=%v want %v", issuer, got, want)
		}
	}
	var nilFile *TrustFile
	if nilFile.Allows("https://accounts.google.com") {
		t.Fatal("nil allowed")
	}
	onlyPattern, err := ParseTrust([]byte(`issuer_patterns = ['https://accounts\.google\.com']`))
	if err != nil || !onlyPattern.Allows("https://accounts.google.com") {
		t.Fatal(err)
	}
}
