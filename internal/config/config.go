// Package config loads and validates the server's environment configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const GoogleIssuer = "https://accounts.google.com"
const ActionsIssuer = "https://token.actions.githubusercontent.com"

var KeyVersion = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[1-9][0-9]*$`)
var Name = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)

func ValidName(s string) bool {
	return (Name.MatchString(s) || s == ".github") && !strings.Contains(s, "..")
}

const (
	DefaultMaxConcurrent = 16
	DefaultExchangeRate  = 60
	DefaultExchangeBurst = 10
)

type Config struct {
	MaxConcurrent, ExchangeRate, ExchangeBurst                               int
	AppID, Identifier, KeySource, KMSKey, KeyFile, KeyEnv                    string
	AllowedAudiences, AllowedIssuers, AllowedOrgs                            []string
	PolicyPrefix, PolicyExtension, OrgPolicyRepo, GitHubURL, LogFormat, Port string
}

func Load() (Config, error) {
	c := Config{AppID: os.Getenv("GSTS_GITHUB_APP_ID"), Identifier: os.Getenv("GSTS_IDENTIFIER"), KeySource: os.Getenv("GSTS_KEY_SOURCE"), KMSKey: os.Getenv("GSTS_KMS_KEY"), KeyFile: os.Getenv("GSTS_KEY_FILE"), KeyEnv: os.Getenv("GSTS_KEY_ENV"), AllowedIssuers: split(value("GSTS_ALLOWED_ISSUERS", GoogleIssuer+","+ActionsIssuer)), AllowedOrgs: split(os.Getenv("GSTS_ALLOWED_ORGS")), PolicyPrefix: value("GSTS_POLICY_PATH_PREFIX", ".github/gsts"), PolicyExtension: value("GSTS_POLICY_FILE_EXTENSION", ".sts.toml"), OrgPolicyRepo: value("GSTS_ORG_POLICY_REPO", ".github"), GitHubURL: value("GSTS_GITHUB_API_URL", "https://api.github.com"), LogFormat: value("GSTS_LOG_FORMAT", "json"), Port: value("PORT", "8080")}
	c.AllowedAudiences = split(value("GSTS_ALLOWED_AUDIENCES", c.Identifier))
	if len(c.AllowedAudiences) == 0 {
		return c, fmt.Errorf("GSTS_ALLOWED_AUDIENCES must be nonempty")
	}
	for _, audience := range c.AllowedAudiences {
		if len(audience) > 2048 || strings.ContainsAny(audience, "\r\n\t") {
			return c, fmt.Errorf("invalid allowed audience")
		}
	}
	for _, setting := range []struct {
		name              string
		target            *int
		fallback, maximum int
	}{
		{"GSTS_MAX_CONCURRENT_EXCHANGES", &c.MaxConcurrent, DefaultMaxConcurrent, 10000},
		{"GSTS_EXCHANGE_RATE_PER_MINUTE", &c.ExchangeRate, DefaultExchangeRate, 1000000},
		{"GSTS_EXCHANGE_BURST", &c.ExchangeBurst, DefaultExchangeBurst, 1000000},
	} {
		n, err := strconv.Atoi(value(setting.name, strconv.Itoa(setting.fallback)))
		if err != nil || n < 1 || n > setting.maximum {
			return c, fmt.Errorf("%s must be between 1 and %d", setting.name, setting.maximum)
		}
		*setting.target = n
	}
	if n, err := strconv.ParseUint(c.AppID, 10, 64); err != nil || n == 0 {
		return c, fmt.Errorf("GSTS_GITHUB_APP_ID must be a positive integer")
	}
	u, err := url.Parse(c.Identifier)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return c, fmt.Errorf("GSTS_IDENTIFIER must be an HTTPS URL (HTTP allowed on localhost)")
	}
	switch c.KeySource {
	case "kms":
		if !KeyVersion.MatchString(c.KMSKey) {
			return c, fmt.Errorf("GSTS_KMS_KEY must identify a numeric CryptoKeyVersion")
		}
	case "file", "env":
		if os.Getenv("GSTS_ALLOW_INSECURE_KEY") != "1" {
			return c, fmt.Errorf("file/env keys require GSTS_ALLOW_INSECURE_KEY=1; use only for local development")
		}
		if (c.KeySource == "file" && c.KeyFile == "") || (c.KeySource == "env" && c.KeyEnv == "") {
			return c, fmt.Errorf("key source configuration is missing")
		}
	default:
		return c, fmt.Errorf("GSTS_KEY_SOURCE must be kms, file, or env")
	}
	for _, iss := range c.AllowedIssuers {
		if iss != GoogleIssuer && iss != ActionsIssuer {
			return c, fmt.Errorf("unsupported issuer %q: v0.1 supports Google and GitHub Actions", iss)
		}
	}
	if len(c.AllowedIssuers) == 0 {
		return c, fmt.Errorf("at least one issuer required")
	}
	for _, org := range c.AllowedOrgs {
		if !ValidName(org) {
			return c, fmt.Errorf("invalid allowed org")
		}
	}
	if strings.HasPrefix(c.PolicyPrefix, "/") || path.Clean(c.PolicyPrefix) != c.PolicyPrefix || strings.Contains(c.PolicyPrefix, "..") || strings.ContainsAny(c.PolicyPrefix, `\?#`) {
		return c, fmt.Errorf("invalid policy prefix")
	}
	if !regexp.MustCompile(`^\.[A-Za-z0-9.]+$`).MatchString(c.PolicyExtension) || !ValidName(c.OrgPolicyRepo) {
		return c, fmt.Errorf("invalid policy extension or org policy repository")
	}
	u, err = url.Parse(c.GitHubURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, fmt.Errorf("GSTS_GITHUB_API_URL must be HTTPS")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		return c, fmt.Errorf("GSTS_LOG_FORMAT must be json or text")
	}
	if p, err := strconv.Atoi(c.Port); err != nil || p < 1 || p > 65535 {
		return c, fmt.Errorf("invalid PORT")
	}
	return c, nil
}
func value(k, d string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return d
}
func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
