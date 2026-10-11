// Package github is the narrow GitHub API surface needed for token exchange.
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type APIError struct {
	RetryAfter  string
	RequestID   string
	Status      int
	RateLimited bool
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API HTTP %d (rate_limited=%t)", e.Status, e.RateLimited)
}

// IsNotFound reports whether err is a GitHub HTTP 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == 404
}

type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
	expires time.Time
}
type Token struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions"`
}
type Client struct {
	BaseURL       string
	HTTP          *http.Client
	mu            sync.Mutex
	installations map[string]Installation
}

func New(base string) *Client {
	return &Client{BaseURL: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("GitHub redirect refused") }}, installations: map[string]Installation{}}
}

func (c *Client) call(ctx context.Context, method, path, auth string, body, out any) error {
	var b []byte
	var err error
	if body != nil {
		b, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "gsts")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Inspect only rate-limit markers; never retain upstream token-bearing bodies.
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		limited := resp.StatusCode == 429 || (resp.StatusCode == 403 && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" || bytes.Contains(bytes.ToLower(data), []byte("rate limit"))))
		return &APIError{Status: resp.StatusCode, RateLimited: limited, RetryAfter: retryAfter(resp.Header, limited, time.Now()), RequestID: safeRequestID(resp.Header.Get("X-GitHub-Request-Id"))}
	}
	if out == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return errors.New("GitHub response too large")
	}
	return json.Unmarshal(data, out)
}
func (c *Client) Installation(ctx context.Context, owner, jwt string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := strings.ToLower(owner)
	if i, ok := c.installations[key]; ok && time.Now().Before(i.expires) {
		return i.ID, nil
	}
	var i Installation
	if err := c.call(ctx, "GET", "/orgs/"+url.PathEscape(owner)+"/installation", jwt, nil, &i); err != nil {
		return 0, err
	}
	if i.ID <= 0 || !strings.EqualFold(i.Account.Login, owner) || i.Account.Type != "Organization" {
		return 0, errors.New("installation owner mismatch")
	}
	i.expires = time.Now().Add(10 * time.Minute)
	if len(c.installations) >= 1000 {
		clear(c.installations)
	}
	c.installations[key] = i
	return i.ID, nil
}
func (c *Client) CreateToken(ctx context.Context, id int64, jwt string, perms map[string]string, repos []string) (Token, error) {
	var token Token
	if len(perms) == 0 || (repos != nil && len(repos) == 0) {
		return token, errors.New("empty token scope")
	}
	body := struct {
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories,omitempty"`
	}{perms, repos}
	err := c.call(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", id), jwt, body, &token)
	if err == nil && (token.Token == "" || token.ExpiresAt.Before(time.Now())) {
		err = errors.New("invalid installation token response")
	}
	return token, err
}

// Head resolves the current head commit of the repository's default branch.
// Callers pin subsequent Policy reads to the returned SHA.
func (c *Client) Head(ctx context.Context, owner, repo, token string) (string, error) {
	// The commit list omits file diffs, so the response stays small for any
	// commit; the single-commit endpoint would include every patch.
	var commits []struct {
		SHA string `json:"sha"`
	}
	if err := c.call(ctx, "GET", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/commits?per_page=1", token, nil, &commits); err != nil {
		return "", err
	}
	if len(commits) != 1 || len(commits[0].SHA) != 40 {
		return "", errors.New("invalid head commit SHA")
	}
	for _, c := range commits[0].SHA {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", errors.New("invalid head commit SHA")
		}
	}
	return commits[0].SHA, nil
}

// Policy reads a file at ref (a commit SHA from Head).
func (c *Client) Policy(ctx context.Context, owner, repo, path, ref, token string) ([]byte, error) {
	var content struct {
		Type, Encoding, Content string
		Size                    int
	}
	err := c.call(ctx, "GET", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contents/"+path+"?ref="+url.QueryEscape(ref), token, nil, &content)
	if err != nil {
		return nil, err
	}
	if content.Type != "file" || content.Encoding != "base64" || content.Size > 65536 {
		return nil, errors.New("policy must be a regular file of at most 64 KiB")
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("policy too large")
	}
	return b, nil
}
func (c *Client) Revoke(ctx context.Context, token string) error {
	return c.call(ctx, "DELETE", "/installation/token", token, nil, nil)
}
func (c *Client) AppPermissions(ctx context.Context, jwt string) (map[string]string, error) {
	var app struct {
		Permissions map[string]string `json:"permissions"`
	}
	err := c.call(ctx, "GET", "/app", jwt, nil, &app)
	return app.Permissions, err
}

// retryAfter preserves valid Retry-After values and translates the primary
// rate-limit reset into seconds. No request, especially token minting, is retried.
func retryAfter(h http.Header, limited bool, now time.Time) string {
	if !limited {
		return ""
	}
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if n, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return strconv.FormatUint(n, 10)
	}
	if date, err := http.ParseTime(raw); err == nil {
		return date.UTC().Format(http.TimeFormat)
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil && reset >= 0 && reset <= 253402300799 {
			return strconv.FormatInt(max(1, reset-now.Unix()), 10)
		}
	}
	return "60"
}
func safeRequestID(id string) string {
	if len(id) > 128 {
		return ""
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ':' || c == '-') {
			return ""
		}
	}
	return id
}
