// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	csrfHeader     = "X-CSRF-Token"
	requestTimeout = 30 * time.Second
	listPageSize   = 200
	maxErrorBody   = 1024
)

// apiClient talks to one nuxd as one signed-in user. It keeps the session cookie in a jar and
// sends the CSRF token and a same-origin Origin on every change, as the browser does.
type apiClient struct {
	base string
	http *http.Client
	// stream has no overall timeout, for SSE and WebSocket reads that run for a long time.
	stream *http.Client
	csrf   string
}

// apiError is a non-2xx answer with the API's error body.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// response is the status, headers and body of one call.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// newAPIClient returns a client that trusts the stack's CA and keeps its own cookie jar. Each
// signed-in user needs its own client, so a scoped viewer's session never leaks into admin calls.
func newAPIClient(base, caPath string) (*apiClient, error) {
	pem, err := os.ReadFile(caPath) //nolint:gosec // path written by stack-up.sh
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA certificate %s holds no PEM certificate", caPath)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie jar: %w", err)
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 8,
	}
	return &apiClient{
		base:   strings.TrimSuffix(base, "/"),
		http:   &http.Client{Jar: jar, Transport: transport, Timeout: requestTimeout},
		stream: &http.Client{Jar: jar, Transport: transport},
	}, nil
}

// call sends one request and returns whatever came back, including error statuses.
func (c *apiClient) call(ctx context.Context, method, path string, body any, hdr http.Header) (response, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return response{}, fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return response{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set(csrfHeader, c.csrf)
		req.Header.Set("Origin", c.base)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return response{}, fmt.Errorf("%s %s: read body: %w", method, path, err)
	}
	return response{Status: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

// do sends a request, requires a 2xx answer and decodes the JSON body into out when out is set.
func (c *apiClient) do(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.call(ctx, method, path, body, nil)
	if err != nil {
		return err
	}
	if resp.Status < 200 || resp.Status > 299 {
		return apiErr(resp)
	}
	if out == nil || len(resp.Body) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("%s %s: decode: %w", method, path, err)
	}
	return nil
}

// decodeBody decodes a response body that the caller already read with call.
func decodeBody(resp response, out any) error {
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// apiErr reads the API's error envelope; anything else is reported with a short raw excerpt.
func apiErr(resp response) error {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &env) == nil && env.Error.Code != "" {
		return &apiError{Status: resp.Status, Code: env.Error.Code, Message: env.Error.Message}
	}
	excerpt := resp.Body
	if len(excerpt) > maxErrorBody {
		excerpt = excerpt[:maxErrorBody]
	}
	return &apiError{Status: resp.Status, Message: string(excerpt)}
}

// asAPIError reports whether err is an API error with the given HTTP status.
func asAPIError(err error, status int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == status
}

// login signs in with email and password and keeps the session cookie and CSRF token.
func (c *apiClient) login(ctx context.Context, email, password string) error {
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/login", map[string]string{"email": email, "password": password}, &out); err != nil {
		return fmt.Errorf("login as %s: %w", email, err)
	}
	c.csrf = out.CSRFToken
	return nil
}

// listAll pages through a cursor-based list endpoint and returns every item.
func listAll[T any](ctx context.Context, c *apiClient, path string) ([]T, error) {
	var all []T
	cursor := ""
	for {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		q := url.Values{"limit": {fmt.Sprint(listPageSize)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			Items      []T     `json:"items"`
			NextCursor *string `json:"next_cursor"`
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

// etagOf returns the ETag of a GET response for use as If-Match on the next change.
func etagOf(resp response) string {
	return resp.Header.Get("ETag")
}

// inventoryEvent is one message from GET /api/v1/events; only the fields the scenarios read.
type inventoryEvent struct {
	Type string `json:"type"`
	Item struct {
		ID string `json:"id"`
	} `json:"item"`
}

// streamEvents opens the SSE inventory stream and delivers each decoded event on the returned
// channel until ctx ends. The channel closes when the stream does.
func (c *apiClient) streamEvents(ctx context.Context) (<-chan inventoryEvent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/events", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.stream.Do(req)
	if err != nil {
		return nil, fmt.Errorf("open events stream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
		return nil, apiErr(response{Status: resp.StatusCode, Body: body})
	}
	out := make(chan inventoryEvent, 256)
	go func() {
		defer close(out)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data:")
			if !ok {
				continue
			}
			var ev inventoryEvent
			if json.Unmarshal([]byte(strings.TrimSpace(data)), &ev) != nil {
				continue
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// dialLogs opens the live log WebSocket for target. A refused upgrade returns the HTTP error.
func (c *apiClient) dialLogs(ctx context.Context, target string, tail int) (*websocket.Conn, error) {
	wsURL := strings.Replace(c.base, "https://", "wss://", 1) + "/api/v1/logs/stream?" +
		url.Values{"target": {target}, "tail": {fmt.Sprint(tail)}}.Encode()
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: c.stream})
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
			_ = resp.Body.Close()
			return nil, apiErr(response{Status: resp.StatusCode, Body: body})
		}
		return nil, fmt.Errorf("dial logs: %w", err)
	}
	return conn, nil
}

// logLine is the text part of a LogFrame of type line.
type logLine struct {
	Type   string `json:"type"`
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

// readLogLines reads frames until one line containing want arrives or ctx ends.
func readLogLines(ctx context.Context, conn *websocket.Conn, want string) (bool, error) {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return false, err
		}
		var f logLine
		if json.Unmarshal(data, &f) != nil {
			continue
		}
		if f.Type == "line" && strings.Contains(f.Text, want) {
			return true, nil
		}
	}
}
