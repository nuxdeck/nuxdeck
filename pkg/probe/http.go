// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// HTTPSpec describes an HTTP(S) check. Headers already carry any resolved credentials.
type HTTPSpec struct {
	URL            string
	Method         string
	Headers        map[string]string
	Body           []byte
	ExpectedStatus []int // empty means any 2xx
	Keyword        string
	JSONPath       string
	JSONOp         string
	JSONValue      string
	VerifyTLS      bool
	MaxRedirects   int
	MaxBodyBytes   int
}

var errTooManyRedirects = errors.New("too many redirects")

func (r *Runner) runHTTP(ctx context.Context, s *HTTPSpec) Result {
	maxBody := s.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	tr := &http.Transport{
		Proxy:                  nil, // environment proxies would bypass the guard
		DialContext:            r.Policy.DialContext(0),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !s.VerifyTLS}, //nolint:gosec // per-check opt-out, off by default
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  0,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > s.MaxRedirects {
			return errTooManyRedirects
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to scheme %q: %w", req.URL.Scheme, ErrBlocked)
		}
		return nil // the dialer re-validates the resolved address of every hop
	}}

	method := s.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if len(s.Body) > 0 {
		body = bytes.NewReader(s.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.URL, body)
	if err != nil {
		return down(errcode.CHKHTTP001, "bad request", 0)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "NuxDeck-Check/1")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		lat := time.Since(start)
		switch {
		case errors.Is(err, errTooManyRedirects):
			return down(errcode.CHKHTTP005, "", lat)
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return down(errcode.CHKHTTP001, "timeout", lat)
		}
		return down(classifyNet(err, errcode.CHKHTTP001), "", lat)
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)))
	lat := time.Since(start)
	if readErr != nil && len(data) == 0 && ctx.Err() != nil {
		return down(errcode.CHKHTTP001, "timeout", lat)
	}

	if !statusOK(resp.StatusCode, s.ExpectedStatus) {
		return down(errcode.CHKHTTP002, "status "+strconv.Itoa(resp.StatusCode), lat)
	}
	if s.Keyword != "" && !bytes.Contains(data, []byte(s.Keyword)) {
		return down(errcode.CHKHTTP003, "", lat)
	}
	if s.JSONPath != "" {
		ok, err := matchJSON(data, s.JSONPath, s.JSONOp, s.JSONValue)
		if err != nil || !ok {
			return down(errcode.CHKHTTP004, "", lat)
		}
	}
	return Result{Status: StatusUp, Latency: lat}
}

func statusOK(code int, expected []int) bool {
	if len(expected) == 0 {
		return code >= 200 && code < 300
	}
	return slices.Contains(expected, code)
}
