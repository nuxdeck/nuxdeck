// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e drives a Docker Compose stack of nuxd, two agents with sockguard sidecars, an nginx
// container and a deliberately failing service through the REST API. The stack is started by
// test/e2e/stack-up.sh (make e2e-up, or make e2e, which also tears it down).
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stackEnv is the configuration stack-up.sh writes to .stack/env.
type stackEnv struct {
	Project       string
	ComposeFile   string
	StackDir      string
	BaseURL       string
	RestoreURL    string
	AdminEmail    string
	AdminPassword string
	CAPEM         string
}

// stackEnvFromOS reads the configuration from the environment and names every missing variable.
func stackEnvFromOS() (stackEnv, error) {
	var missing []string
	get := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}
	env := stackEnv{
		Project:       get("E2E_PROJECT"),
		ComposeFile:   get("E2E_COMPOSE_FILE"),
		StackDir:      get("E2E_STACK_DIR"),
		BaseURL:       get("E2E_BASE_URL"),
		RestoreURL:    get("E2E_RESTORE_URL"),
		AdminEmail:    get("E2E_ADMIN_EMAIL"),
		AdminPassword: get("E2E_ADMIN_PASSWORD"),
		CAPEM:         get("E2E_CA_PEM"),
	}
	if len(missing) > 0 {
		return stackEnv{}, fmt.Errorf("%s not set; run through make e2e or source test/e2e/.stack/env", strings.Join(missing, ", "))
	}
	return env, nil
}

// compose runs Docker Compose against this stack's project only and returns stdout. Stderr is
// included in the error, so a failing step explains itself in the test log.
func (e stackEnv) compose(ctx context.Context, args ...string) (string, error) {
	full := append([]string{
		"compose", "--env-file", filepath.Join(e.StackDir, "compose.env"),
		"-p", e.Project, "-f", e.ComposeFile,
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...) //nolint:gosec // fixed binary; arguments come from the harness
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("docker compose %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// pollInterval is how often eventually re-checks a condition. Deadlines come from the caller.
const pollInterval = 500 * time.Millisecond

// eventually calls check until it reports done, failing the test at the deadline. check returns
// a description of what it saw, for the failure message.
func eventually(t testing.TB, within time.Duration, what string, check func() (done bool, detail string, err error)) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(within)
	var last string
	for {
		done, detail, err := check()
		if done && err == nil {
			return time.Since(start)
		}
		last = detail
		if err != nil {
			last = fmt.Sprintf("%s (error: %v)", detail, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s; last seen: %s", within, what, last)
		}
		time.Sleep(pollInterval)
	}
}

// randomToken returns a short hex string for names and probe lines that must not collide.
func randomToken(t testing.TB) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random token: %v", err)
	}
	return hex.EncodeToString(b)
}

// webhookReceiver accepts alert notifications posted by nuxd. nuxd reaches it through
// host.docker.internal, so it listens on every interface, and the path carries a random secret
// so that nothing else on the network can post to it.
type webhookReceiver struct {
	URL      string
	server   *http.Server
	requests chan []byte
}

func startWebhookReceiver(t testing.TB) *webhookReceiver {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen for webhooks: %v", err)
	}
	secret := randomToken(t)
	rcv := &webhookReceiver{requests: make(chan []byte, 64)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hook/"+secret, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		select {
		case rcv.requests <- body:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rcv.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = rcv.server.Serve(ln) }()
	t.Cleanup(func() { _ = rcv.server.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	// The stack reaches the host through host.docker.internal (see compose.yaml).
	rcv.URL = fmt.Sprintf("http://host.docker.internal:%d/hook/%s", port, secret)
	return rcv
}

// httpStatusOK reports whether a plain GET of url answers 200; used for readiness probes.
func httpStatusOK(ctx context.Context, client *http.Client, url string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}
