// Package policy implements fail-closed trust policy validation and evaluation.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pelletier/go-toml/v2"
	"github.com/sakajunquality/gsts/internal/config"
)

type Google struct {
	ServiceAccount        string `toml:"service_account"`
	ServiceAccountPattern string `toml:"service_account_pattern"`
	Project               string `toml:"project"`
}
type Policy struct {
	Issuer          string            `toml:"issuer"`
	IssuerPattern   string            `toml:"issuer_pattern"`
	Subject         string            `toml:"subject"`
	SubjectPattern  string            `toml:"subject_pattern"`
	Audience        string            `toml:"audience"`
	AudiencePattern string            `toml:"audience_pattern"`
	ClaimPattern    map[string]string `toml:"claim_pattern"`
	// Claim holds exact-match claims. Parse guarantees every value is a
	// string, int64 or bool.
	Claim            map[string]any    `toml:"claim"`
	MaxTokenLifetime int64             `toml:"max_token_lifetime"`
	Permissions      map[string]string `toml:"permissions"`
	Repositories     []string          `toml:"repositories"`
	Google           *Google           `toml:"google"`
}

func Parse(b []byte, org bool) (*Policy, error) {
	var p Policy
	if err := toml.NewDecoder(bytes.NewReader(b)).DisallowUnknownFields().Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid TOML: %w", err)
	}
	if p.Google == nil && ((p.Issuer == "" && p.IssuerPattern == "") || (p.Subject == "" && p.SubjectPattern == "")) {
		return nil, fmt.Errorf("issuer and subject constraints required")
	}
	if p.MaxTokenLifetime < 0 {
		return nil, fmt.Errorf("negative max_token_lifetime")
	}
	if p.Claim != nil {
		if len(p.Claim) == 0 {
			return nil, fmt.Errorf("empty claim is ambiguous; omit it instead")
		}
		for k, v := range p.Claim {
			if k == "" {
				return nil, fmt.Errorf("empty claim name")
			}
			switch v.(type) {
			case string, int64, bool:
			default:
				return nil, fmt.Errorf("claim %s: claim values must be strings, integers or booleans", k)
			}
		}
	}
	patterns := []string{p.IssuerPattern, p.SubjectPattern, p.AudiencePattern}
	for _, v := range p.ClaimPattern {
		patterns = append(patterns, v)
	}
	if p.Google != nil {
		g := p.Google
		count := 0
		for _, v := range []string{g.ServiceAccount, g.ServiceAccountPattern, g.Project} {
			if v != "" {
				count++
			}
		}
		if count != 1 {
			return nil, fmt.Errorf("google requires exactly one account selector")
		}
		if g.ServiceAccount != "" && !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.gserviceaccount\.com$`).MatchString(g.ServiceAccount) {
			return nil, fmt.Errorf("invalid service account email")
		}
		if g.Project != "" && !regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`).MatchString(g.Project) {
			return nil, fmt.Errorf("invalid Google project ID")
		}
		patterns = append(patterns, g.ServiceAccountPattern)
	}
	for _, v := range patterns {
		if _, err := regexp.Compile("^(?:" + v + ")$"); err != nil {
			return nil, fmt.Errorf("invalid pattern: %w", err)
		}
	}
	if len(p.Permissions) == 0 {
		return nil, fmt.Errorf("permissions must be nonempty")
	}
	for k, v := range p.Permissions {
		if !org && !repositoryPermissions[k] {
			return nil, fmt.Errorf("permission %s requires an org-level policy", k)
		}
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(k) || (v != "read" && v != "write") {
			return nil, fmt.Errorf("invalid permission")
		}
	}
	if !org && p.Repositories != nil {
		return nil, fmt.Errorf("repositories is only valid for org policies")
	}
	if p.Repositories != nil && len(p.Repositories) == 0 {
		return nil, fmt.Errorf("empty repositories is ambiguous; omit for all installed repositories")
	}
	for _, r := range p.Repositories {
		if !config.ValidName(r) {
			return nil, fmt.Errorf("invalid repository")
		}
	}
	return &p, nil
}

func matches(v, exact, pattern string) bool {
	if exact != "" && v != exact {
		return false
	}
	if pattern != "" {
		r, err := regexp.Compile("^(?:" + pattern + ")$")
		return err == nil && r.MatchString(v)
	}
	return true
}

// claimEquals is strict: types never coerce, and missing or non-scalar claims
// never match. Numeric claims (json.Number) match only integer policy values.
func claimEquals(got, want any) bool {
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		return ok && g == w
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case int64:
		n, ok := got.(json.Number)
		if !ok {
			return false
		}
		g, err := strconv.ParseInt(n.String(), 10, 64)
		return err == nil && g == w
	}
	return false
}

// Evaluate only accepts claims whose signature and timestamps have been verified.
func (p *Policy) Evaluate(c jwt.MapClaims, identifier string) error {
	iss, _ := c["iss"].(string)
	sub, _ := c["sub"].(string)
	if !matches(iss, p.Issuer, p.IssuerPattern) || !matches(sub, p.Subject, p.SubjectPattern) {
		return fmt.Errorf("issuer or subject mismatch")
	}
	aud, err := c.GetAudience()
	if err != nil || len(aud) == 0 {
		return fmt.Errorf("missing audience")
	}
	exact, pattern := p.Audience, p.AudiencePattern
	if exact == "" && pattern == "" {
		exact = identifier
	}
	ok := false
	for _, a := range aud {
		if a != "" && matches(a, exact, pattern) {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("audience mismatch")
	}
	if p.Google != nil {
		g := p.Google
		email, _ := c["email"].(string)
		verified, _ := c["email_verified"].(bool)
		if iss != config.GoogleIssuer || !verified || email == "" {
			return fmt.Errorf("Google verified email required")
		}
		pattern := g.ServiceAccountPattern
		if g.Project != "" {
			pattern = `[^@\s]+@` + regexp.QuoteMeta(g.Project) + `\.iam\.gserviceaccount\.com`
		}
		if !matches(email, g.ServiceAccount, pattern) {
			return fmt.Errorf("Google account mismatch")
		}
	}
	for k, want := range p.Claim {
		if !claimEquals(c[k], want) {
			return fmt.Errorf("claim %s mismatch", k)
		}
	}
	for k, pattern := range p.ClaimPattern {
		value, exists := c[k]
		if !exists {
			return fmt.Errorf("missing claim %s", k)
		}
		var s string
		switch v := value.(type) {
		case string:
			s = v
		case bool:
			if v {
				s = "true"
			} else {
				s = "false"
			}
		case json.Number:
			s = v.String()
		default:
			return fmt.Errorf("non-scalar claim %s", k)
		}
		r, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil || !r.MatchString(s) {
			return fmt.Errorf("claim %s mismatch", k)
		}
	}
	if p.MaxTokenLifetime > 0 {
		exp, e1 := c.GetExpirationTime()
		iat, e2 := c.GetIssuedAt()
		if e1 != nil || e2 != nil || exp == nil || iat == nil || exp.Unix()-iat.Unix() > p.MaxTokenLifetime {
			return fmt.Errorf("token lifetime exceeded")
		}
	}
	return nil
}

// Narrow never turns an explicit empty list/map into GitHub's implicit full access.
func (p *Policy) Narrow(perms map[string]string, repos []string, repo string) (map[string]string, []string, error) {
	if perms == nil {
		perms = p.Permissions
	} else {
		if len(perms) == 0 {
			return nil, nil, fmt.Errorf("empty permissions")
		}
		for k, v := range perms {
			max, ok := p.Permissions[k]
			if !ok || (v != "read" && v != "write") || (max == "read" && v != "read") {
				return nil, nil, fmt.Errorf("permission exceeds policy")
			}
		}
	}
	if repo != "" {
		if repos != nil {
			return nil, nil, fmt.Errorf("repository narrowing requires org scope")
		}
		return perms, []string{repo}, nil
	}
	if repos == nil {
		repos = p.Repositories
	} else {
		if len(repos) == 0 {
			return nil, nil, fmt.Errorf("empty repositories")
		}
		for _, r := range repos {
			if !config.ValidName(r) {
				return nil, nil, fmt.Errorf("invalid repository")
			}
			if p.Repositories != nil && !slices.ContainsFunc(p.Repositories, func(allowed string) bool { return strings.EqualFold(r, allowed) }) {
				return nil, nil, fmt.Errorf("repository exceeds policy")
			}
		}
	}
	return perms, repos, nil
}

// Repository policies must never authorize organization-wide capabilities.
// Unknown permissions require an org policy until their scope is reviewed.
var repositoryPermissions = func() map[string]bool {
	out := map[string]bool{}
	for _, name := range strings.Fields(`actions administration artifact_metadata attestations checks code_quality codespaces contents dependabot_secrets deployments discussions environments issues merge_queues metadata packages pages pull_requests repository_custom_properties repository_hooks repository_projects secret_scanning_alerts secrets security_events single_file statuses vulnerability_alerts workflows interaction_limits`) {
		out[name] = true
	}
	return out
}()
