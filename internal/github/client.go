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
	"strings"
	"sync"
	"time"
)

type APIError struct {
	Status      int
	RateLimited bool
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API HTTP %d (rate_limited=%t)", e.Status, e.RateLimited)
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
		return &APIError{Status: resp.StatusCode, RateLimited: limited}
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
func (c *Client) Policy(ctx context.Context, owner, repo, path, token string) ([]byte, error) {
	// Omit ref deliberately: GitHub resolves the repository's default branch.
	var content struct {
		Type, Encoding, Content string
		Size                    int
	}
	err := c.call(ctx, "GET", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contents/"+path, token, nil, &content)
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
