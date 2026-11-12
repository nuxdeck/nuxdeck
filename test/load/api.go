// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	csrfHeader    = "X-CSRF-Token"
	listPageSize  = 200
	apiTimeout    = 30 * time.Second
	maxErrorBytes = 512
)

// apiClient talks to nuxd's REST API as the admin created by setup, keeping the session cookie.
type apiClient struct {
	base string
	http *http.Client
	csrf string
}

func newAPIClient(base string) (*apiClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &apiClient{base: base, http: &http.Client{
		Jar:     jar,
		Timeout: apiTimeout,
		// nuxd serves a self-signed certificate to this harness only; the harness runs on loopback.
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed loopback certificate of the child nuxd
			MaxIdleConnsPerHost: 16,
		},
	}}, nil
}

// do sends one request. Mutating requests carry the CSRF token and a same-origin Origin, as the browser UI does.
func (c *apiClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set(csrfHeader, c.csrf)
		req.Header.Set("Origin", c.base)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s %s: decode: %w", method, path, err)
	}
	return nil
}

// setupAdmin completes first-run setup and keeps the CSRF token for later mutations.
func (c *apiClient) setupAdmin(ctx context.Context, setupToken string) error {
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	body := map[string]string{
		"token": setupToken, "name": "Load Harness", "email": "load@example.test", "password": "load harness passphrase 2026",
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/setup/admin", body, &out); err != nil {
		return err
	}
	c.csrf = out.CSRFToken
	return nil
}

// newAgentToken creates one single-use enrolment token.
func (c *apiClient) newAgentToken(ctx context.Context) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/agents/tokens", map[string]int{"ttl_seconds": 3600}, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// createCheck adds one check and returns its ID.
func (c *apiClient) createCheck(ctx context.Context, body map[string]any) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/checks", body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// checkRow is the part of a check the harness reads back to see whether it has run.
type checkRow struct {
	ID     string `json:"id"`
	Status struct {
		LastChecked *time.Time `json:"last_checked"`
	} `json:"status"`
}

// listAll pages through a cursor-based list endpoint.
func listAll[T any](ctx context.Context, c *apiClient, path string) ([]T, error) {
	var all []T
	cursor := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(listPageSize)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			Items      []T     `json:"items"`
			NextCursor *string `json:"next_cursor"`
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		if err := c.do(ctx, http.MethodGet, path+sep+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = *page.NextCursor
	}
}

// onlineHosts counts the hosts nuxd reports online, which is what the UI shows.
func (c *apiClient) onlineHosts(ctx context.Context) (int, error) {
	rows, err := listAll[json.RawMessage](ctx, c, "/api/v1/hosts?status=online")
	return len(rows), err
}

// timedGET performs one read the way a dashboard does and reports how long it took.
func (c *apiClient) timedGET(ctx context.Context, path string) (time.Duration, error) {
	start := time.Now()
	err := c.do(ctx, http.MethodGet, path, nil, nil)
	return time.Since(start), err
}
