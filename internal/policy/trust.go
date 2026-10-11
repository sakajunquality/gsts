package policy

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"

	"github.com/pelletier/go-toml/v2"
)

// TrustFile is an organization's enforce-only issuer allowlist. It can only
// narrow the deployment-wide GSTS_ALLOWED_ISSUERS; it never adds issuers.
type TrustFile struct {
	Issuers        []string `toml:"issuers"`
	IssuerPatterns []string `toml:"issuer_patterns"`
	patterns       []*regexp.Regexp
}

// ParseTrust parses and validates a trusted-issuers file. Unknown keys, empty
// entries and a file with no issuers and no patterns are errors: an empty list
// never means "all issuers".
func ParseTrust(b []byte) (*TrustFile, error) {
	var t TrustFile
	if err := toml.NewDecoder(bytes.NewReader(b)).DisallowUnknownFields().Decode(&t); err != nil {
		return nil, fmt.Errorf("invalid TOML: %w", err)
	}
	if len(t.Issuers) == 0 && len(t.IssuerPatterns) == 0 {
		return nil, fmt.Errorf("issuers or issuer_patterns must be nonempty")
	}
	for _, v := range t.Issuers {
		if v == "" {
			return nil, fmt.Errorf("empty issuer")
		}
	}
	for _, v := range t.IssuerPatterns {
		if v == "" {
			return nil, fmt.Errorf("empty issuer pattern")
		}
		r, err := regexp.Compile("^(?:" + v + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid pattern: %w", err)
		}
		t.patterns = append(t.patterns, r)
	}
	return &t, nil
}

// Allows reports whether the verified issuer is listed or matches a pattern.
func (t *TrustFile) Allows(issuer string) bool {
	if t == nil || issuer == "" {
		return false
	}
	if slices.Contains(t.Issuers, issuer) {
		return true
	}
	return slices.ContainsFunc(t.patterns, func(r *regexp.Regexp) bool { return r.MatchString(issuer) })
}
