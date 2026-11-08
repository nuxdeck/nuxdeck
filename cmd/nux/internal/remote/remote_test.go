// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const testToken = "nuxt_test_secret_0123456789abcdef"

const (
	hostID      = "01HOSTAAAAAAAAAAAAAAAAAAAA"
	apiCtrID    = "01CTRAAAAAAAAAAAAAAAAAAAAA"
	apiCtrDupID = "01CTRBBBBBBBBBBBBBBBBBBBBB"
	dbCtrID     = "01CTRDDDDDDDDDDDDDDDDDDDDD"
)

// harness is a TLS nuxd stand-in. It checks the bearer token on every request and answers the
// endpoints from routes; unknown paths get a 404 in the shared error shape.
type harness struct {
	srv    *httptest.Server
	pin    string
	routes map[string]http.HandlerFunc
	mu     sync.Mutex
	seen   []*http.Request
}

// requests returns the requests seen so far.
func (h *harness) requests() []*http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*http.Request(nil), h.seen...)
}

func newHarness(t *testing.T, routes map[string]http.HandlerFunc) *harness {
	t.Helper()
	h := &harness{routes: routes}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.seen = append(h.seen, r.Clone(r.Context()))
		h.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			writeErr(w, http.StatusUnauthorized, "AUTH-TOKEN-001", "token not accepted", "Sign in again.")
			return
		}
		key := r.Method + " " + r.URL.Path
		if fn, ok := h.routes[key]; ok {
			fn(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "API-NF-001", "not found", "Check the ID.")
	}))
	t.Cleanup(h.srv.Close)
	sum := sha256.Sum256(h.srv.Certificate().Raw)
	h.pin = "sha256:" + hex.EncodeToString(sum[:])
	return h
}

func writeErr(w http.ResponseWriter, status int, code, msg, hint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg, "hint": hint}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// nux runs the remote command with a private config directory and the harness pinned.
type result struct {
	code           int
	stdout, stderr string
}

func (h *harness) nux(t *testing.T, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	cfgHome := t.TempDir()
	if env == nil {
		env = map[string]string{}
	}
	env["XDG_CONFIG_HOME"] = cfgHome
	return runWith(t, env, stdin, args)
}

func runWith(t *testing.T, env map[string]string, stdin string, args []string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	e := Env{
		Stdin:         strings.NewReader(stdin),
		Stdout:        &out,
		Stderr:        &errOut,
		Getenv:        func(k string) string { return env[k] },
		UserConfigDir: func() (string, error) { return "", errors.New("no user config dir") },
	}
	cmd, rest := args[0], args[1:]
	code := Run(context.Background(), cmd, rest, e, "")
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

// withTarget appends the server and pin, so every test talks to its own harness.
func (h *harness) args(args ...string) []string {
	return append(args, "--server", h.srv.URL, "--pin", h.pin)
}

func (h *harness) defaultRoutes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/v1/me": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"csrf_token": "c", "user": map[string]any{"id": "u1", "email": "ops@example.com", "name": "Ops", "roles": []string{"admin"}}})
		},
		"GET /api/v1/hosts": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("cursor") != "" {
				writeJSON(w, 200, map[string]any{"items": []any{}, "next_cursor": nil})
				return
			}
			writeJSON(w, 200, map[string]any{"items": []any{map[string]any{"id": hostID, "hostname": "web-1", "status": "online", "os": "linux", "arch": "amd64", "cpu_count": 4, "memory_bytes": 1024, "last_seen_at": "2026-10-28T10:00:00Z", "first_seen_at": "2026-10-01T00:00:00Z", "facts": map[string]string{}, "tags": map[string]string{}, "labels": map[string]string{}, "etag": "e1", "agent_id": "01AGENTAAAAAAAAAAAAAAAAAAAA", "owner": "", "distro": "debian", "kernel": "6.1", "gone_at": nil}}, "next_cursor": "cursor-2"})
		},
		"GET /api/v1/hosts/" + hostID: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"id": hostID, "hostname": "web-1", "status": "online", "os": "linux", "arch": "amd64", "cpu_count": 4, "memory_bytes": 1024, "last_seen_at": "2026-10-28T10:00:00Z", "first_seen_at": "2026-10-01T00:00:00Z", "facts": map[string]string{}, "tags": map[string]string{}, "etag": "e1", "agent_id": "01AGENTAAAAAAAAAAAAAAAAAAAA", "owner": "", "distro": "debian", "kernel": "6.1"})
		},
		"GET /api/v1/containers": func(w http.ResponseWriter, _ *http.Request) {
			ct := func(id, name string) map[string]any {
				return map[string]any{"id": id, "name": name, "image": "nginx:1", "state": "running", "host_id": hostID, "runtime": "docker", "runtime_id": "rt", "labels": map[string]string{}, "tags": map[string]string{}, "ports": []any{}, "etag": "e", "owner": "", "restart_count": 0}
			}
			writeJSON(w, 200, map[string]any{"items": []any{ct(apiCtrID, "api"), ct(apiCtrDupID, "api"), ct(dbCtrID, "db")}, "next_cursor": nil})
		},
		"POST /api/v1/checks/01CHKAAAAAAAAAAAAAAAAAAAAA/run": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"status": "up", "latency_ms": 12, "error_code": "", "detail": "HTTP 200", "ts": "2026-10-28T10:00:00Z"})
		},
		"POST /api/v1/alerts/01ALRAAAAAAAAAAAAAAAAAAAAA/ack": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"id": "01ALRAAAAAAAAAAAAAAAAAAAAA", "state": "acked"})
		},
		"POST /api/v1/alerts/01ALRRESOLVEDAAAAAAAAAAA/ack": func(w http.ResponseWriter, _ *http.Request) {
			writeErr(w, http.StatusConflict, "ALR-RULE-001", "Alert already resolved", "Reload the alert list.")
		},
		"POST /api/v1/silences": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["reason"] == "" {
				writeErr(w, http.StatusUnprocessableEntity, "API-VAL-001", "reason required", "Give a reason.")
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{"id": "01SLNAAAAAAAAAAAAAAAAAAAAA", "kind": "silence", "state": "active", "reason": body["reason"], "starts_at": body["starts_at"], "ends_at": body["ends_at"], "selector": body["selector"], "created_at": "2026-10-28T10:00:00Z", "created_by": "u1"})
		},
		"DELETE /api/v1/silences/01SLNAAAAAAAAAAAAAAAAAAAAA": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
		"POST /api/v1/agents/tokens": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{"id": "01TOKAAAAAAAAAAAAAAAAAAAAA", "token": "enrol_once_abc", //nolint:gosec // fixture value, not a credential
				"expires_at": "2026-10-28T11:00:00Z"})
		},
		"GET /api/v1/telemetry/preview": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"schema_version": 1, "install_id": "i1", "nuxd_version": "dev"})
		},
	}
}

func TestCLI2_CommandsAgainstFakeNuxd(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	tests := []struct {
		name     string
		args     []string
		token    bool // whether NUX_TOKEN is provided
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{"hosts ls table", []string{"hosts"}, true, 0, "web-1", "more results: nux hosts ls --cursor cursor-2"},
		{"hosts ls json", []string{"hosts", "ls", "--output", "json"}, true, 0, `"hostname": "web-1"`, ""},
		{"hosts get", []string{"hosts", "get", hostID}, true, 0, "Hostname", ""},
		{"hosts bad status", []string{"hosts", "ls", "--status", "sideways"}, true, 2, "", "CLI-ARG-002"},
		{"hosts bad output", []string{"hosts", "ls", "--output", "yaml"}, true, 2, "", "CLI-ARG-002"},
		{"containers ls", []string{"containers", "ls"}, true, 0, "db", ""},
		{"containers get missing", []string{"containers", "get", "01NOPE"}, true, 4, "", "API-NF-001"},
		{"checks run", []string{"checks", "run", "01CHKAAAAAAAAAAAAAAAAAAAAA"}, true, 0, "up", ""},
		{"alerts ack", []string{"alerts", "ack", "01ALRAAAAAAAAAAAAAAAAAAAAA"}, true, 0, "Acknowledged", ""},
		{"alerts ack resolved is conflict", []string{"alerts", "ack", "01ALRRESOLVEDAAAAAAAAAAA"}, true, 1, "", "ALR-RULE-001"},
		{"silences create", []string{"silences", "create", "--reason", "deploy", "--duration", "2h", "--id", hostID}, true, 0, "Created silence", ""},
		{"silences create needs end", []string{"silences", "create", "--reason", "x"}, true, 2, "", "CLI-ARG-002"},
		{"silences create end before start", []string{"silences", "create", "--reason", "x", "--starts", "2026-10-28T12:00:00Z", "--ends", "2026-10-28T11:00:00Z"}, true, 2, "", "CLI-ARG-002"},
		{"silences rm", []string{"silences", "rm", "01SLNAAAAAAAAAAAAAAAAAAAAA"}, true, 0, "Removed silence", ""},
		{"agents token create prints token once", []string{"agents", "token", "create"}, true, 0, "enrol_once_abc", ""},
		{"agents ls", []string{"agents", "ls"}, true, 0, "01AGENTAAAAAAAAAAAAAAAAAAAA", ""},
		{"telemetry show", []string{"telemetry", "show"}, true, 0, `"install_id": "i1"`, ""},
		{"no token", []string{"hosts", "ls"}, false, 3, "", "CLI-AUTH-001"},
		{"wrong token is auth", []string{"hosts", "ls"}, true, 3, "", "AUTH-TOKEN-001"},
		{"unknown subcommand", []string{"hosts", "explode"}, true, 2, "", "CLI-ARG-001"},
		{"help", []string{"help"}, true, 0, "Exit codes", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"NUX_TOKEN": testToken}
			if !tt.token {
				env = map[string]string{}
			}
			if strings.HasPrefix(tt.name, "wrong token") {
				env["NUX_TOKEN"] = "nuxt_wrong"
			}
			r := h.nux(t, env, "", h.args(tt.args...)...)
			if r.code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", r.code, tt.wantCode, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stdout, tt.wantOut) {
				t.Errorf("stdout lacks %q:\n%s", tt.wantOut, r.stdout)
			}
			if !strings.Contains(r.stdout+r.stderr, tt.wantErr) {
				t.Errorf("output lacks %q:\nstdout: %s\nstderr: %s", tt.wantErr, r.stdout, r.stderr)
			}
			if strings.Contains(r.stdout+r.stderr, testToken) {
				t.Errorf("API token leaked into output")
			}
		})
	}
}

func TestCLI2_AmbiguousTargetNeedsID(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	env := map[string]string{"NUX_TOKEN": testToken}
	r := h.nux(t, env, "", h.args("logs", "api")...)
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2 (ambiguous is a usage error)\nstderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "CLI-ARG-004") || !strings.Contains(r.stderr, apiCtrID) {
		t.Errorf("stderr should name the code and list the candidate IDs: %s", r.stderr)
	}
}

func TestCLI2_SilenceRequestValidation(t *testing.T) {
	now := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		kind    string
		reason  string
		starts  string
		ends    string
		dur     time.Duration
		wantErr bool
		wantEnd time.Time
	}{
		{"duration from now", "silence", "x", "", "", time.Hour, false, now.Add(time.Hour)},
		{"explicit window", "maintenance", "x", "2026-10-28T11:00:00Z", "2026-10-28T12:00:00Z", 0, false, time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)},
		{"both ends and duration", "silence", "x", "", "2026-10-28T12:00:00Z", time.Hour, true, time.Time{}},
		{"no end", "silence", "x", "", "", 0, true, time.Time{}},
		{"bad kind", "pause", "x", "", "", time.Hour, true, time.Time{}},
		{"blank reason", "silence", "  ", "", "", time.Hour, true, time.Time{}},
		{"bad time", "silence", "x", "tomorrow", "", time.Hour, true, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := silenceRequest(tt.kind, tt.reason, tt.starts, tt.ends, tt.dur, nil, nil, nil, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && !req.EndsAt.Equal(tt.wantEnd) {
				t.Errorf("ends = %s, want %s", req.EndsAt, tt.wantEnd)
			}
		})
	}
}

func TestCLI3_TokenFromStdinAndFileNeverPrinted(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := writeFile(tokenFile, testToken+"\n"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		args  []string
		stdin string
		code  int
	}{
		{"token file", []string{"login", "--token-file", tokenFile}, "", 0},
		{"token stdin", []string{"login", "--token-stdin"}, testToken + "\n", 0},
		{"two sources refused", []string{"login", "--token-stdin", "--token-file", tokenFile}, testToken, 2},
		{"no source refused", []string{"login"}, "", 2},
		{"empty stdin refused", []string{"login", "--token-stdin"}, "\n", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := h.nux(t, nil, tt.stdin, h.args(tt.args...)...)
			if r.code != tt.code {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", r.code, tt.code, r.stdout, r.stderr)
			}
			if strings.Contains(r.stdout+r.stderr, testToken) {
				t.Fatalf("token printed:\n%s%s", r.stdout, r.stderr)
			}
		})
	}
}

func TestCLI3_LoginWritesConfigWith0600AndLogoutRemovesIt(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	cfgHome := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": cfgHome}

	r := runWith(t, env, testToken, h.args("login", "--token-stdin"))
	if r.code != 0 {
		t.Fatalf("login exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "ops@example.com") {
		t.Errorf("login should name the account: %s", r.stdout)
	}
	if !strings.Contains(r.stderr, "clear text") {
		t.Errorf("login must warn that the token is stored in clear text: %s", r.stderr)
	}
	path := filepath.Join(cfgHome, "nux", "config.json")
	if LooseMode(path) {
		t.Fatalf("config %s is readable by others", path)
	}
	cfg, found, err := LoadConfig(path)
	if err != nil || !found {
		t.Fatalf("load config: found=%v err=%v", found, err)
	}
	if cfg.Token != testToken || cfg.Pin != h.pin {
		t.Errorf("stored config = %+v", cfg)
	}

	// The stored sign-in is used without any token flag.
	r = runWith(t, env, "", []string{"hosts", "ls", "--server", h.srv.URL, "--pin", h.pin})
	if r.code != 0 {
		t.Fatalf("hosts with stored sign-in exit %d: %s", r.code, r.stderr)
	}

	r = runWith(t, env, "", []string{"logout"})
	if r.code != 0 || !strings.Contains(r.stdout, "Signed out") {
		t.Fatalf("logout exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	r = runWith(t, env, "", []string{"logout"})
	if !strings.Contains(r.stdout, "Not signed in") {
		t.Errorf("second logout should say not signed in: %s", r.stdout)
	}
}

func TestCLI2_LoginRejectsWhenServerRefusesToken(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir()}
	r := runWith(t, env, "nuxt_bad", h.args("login", "--token-stdin"))
	if r.code != 3 {
		t.Fatalf("exit = %d, want 3\nstderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "AUTH-TOKEN-001") {
		t.Errorf("stderr should carry the server code: %s", r.stderr)
	}
}

func TestCLI2_ServerValidation(t *testing.T) {
	env := map[string]string{"NUX_TOKEN": testToken, "XDG_CONFIG_HOME": t.TempDir()}
	for _, server := range []string{"ftp://x", "https://user:pw@x.example", "http://nuxd.example.com"} {
		r := runWith(t, env, "", []string{"hosts", "ls", "--server", server})
		if r.code != 2 {
			t.Errorf("server %q: exit = %d, want 2; stderr %s", server, r.code, r.stderr)
		}
	}
}

func TestCLI2_HelpFlagsExitZero(t *testing.T) {
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir()}
	for _, cmd := range []string{"hosts", "logs", "silences"} {
		r := runWith(t, env, "", []string{cmd, "ls", "-h"})
		if r.code != 0 {
			t.Errorf("%s -h exit = %d", cmd, r.code)
		}
	}
	r := runWith(t, env, "", []string{"logs", "-h"})
	if !strings.Contains(r.stderr, "Usage: nux logs") {
		t.Errorf("logs -h should print usage: %s", r.stderr)
	}
}

func TestCLI2_ExitCodeMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"401 is auth", &APIError{Status: 401}, 3},
		{"403 is auth", &APIError{Status: 403}, 3},
		{"404 is not found", &APIError{Status: 404}, 4},
		{"500 is generic", &APIError{Status: 500}, 1},
		{"not signed in", errcode.New(errcode.CLIAuth001, "x"), 3},
		{"usage", errcode.New(errcode.CLIArg002, "x"), 2},
		{"ambiguous", errcode.New(errcode.CLIArg004, "x"), 2},
		{"unknown code", errcode.New(errcode.CLINet001, "x"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.err); got != tt.want {
				t.Errorf("exitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCLI2_ConfigPathUsesXDG(t *testing.T) {
	got, err := ConfigPath(func(k string) string {
		if k == "XDG_CONFIG_HOME" {
			return "/xdg"
		}
		return ""
	}, func() (string, error) { return "/home/x/.config", nil })
	if err != nil || got != filepath.Join("/xdg", "nux", "config.json") {
		t.Fatalf("ConfigPath = %q, %v", got, err)
	}
}

func TestCLI2_ConfigFileModesAndAtomicReplace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	path := filepath.Join(dir, "nux", "config.json")
	if err := SaveConfig(path, Config{Server: "https://a.example", Token: testToken}); err != nil {
		t.Fatal(err)
	}
	if LooseMode(path) {
		t.Error("config created with group or other access")
	}
	if err := SaveConfig(path, Config{Server: "https://b.example"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadConfig(path)
	if err != nil || cfg.Server != "https://b.example" || cfg.Token != "" {
		t.Fatalf("replace failed: %+v %v", cfg, err)
	}
}

func TestCLI2_LooseConfigWarns(t *testing.T) {
	dir := t.TempDir()
	cfgHome := dir
	path := filepath.Join(cfgHome, "nux", "config.json")
	if err := SaveConfig(path, Config{Server: "https://a.example", Token: testToken}); err != nil {
		t.Fatal(err)
	}
	if err := chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	r := runWith(t, map[string]string{"XDG_CONFIG_HOME": cfgHome}, "", []string{"hosts", "ls", "--server", h.srv.URL, "--pin", h.pin})
	if !strings.Contains(r.stderr, "readable by other users") {
		t.Errorf("expected a loose-permission warning, stderr: %s", r.stderr)
	}
}

func TestCLI2_PinAndFingerprintParsing(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	colons := "SHA256:" + strings.Join(strings.Split(strings.Repeat("ab", 32), ""), "")
	if _, err := parseFingerprint(good); err != nil {
		t.Errorf("valid pin rejected: %v", err)
	}
	if _, err := parseFingerprint(colons); err != nil {
		t.Errorf("uppercase prefix should be accepted: %v", err)
	}
	for _, bad := range []string{"", "md5:" + strings.Repeat("ab", 16), "sha256:zz", "sha256:" + strings.Repeat("ab", 31)} {
		if _, err := parseFingerprint(bad); err == nil {
			t.Errorf("pin %q should be rejected", bad)
		}
	}
}

func TestCLI2_PinMismatchIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	wrong := "sha256:" + strings.Repeat("00", 32)
	env := map[string]string{"NUX_TOKEN": testToken, "XDG_CONFIG_HOME": t.TempDir()}
	r := runWith(t, env, "", []string{"hosts", "ls", "--server", h.srv.URL, "--pin", wrong})
	if r.code != 1 || !strings.Contains(r.stderr, "CLI-NET-002") {
		t.Fatalf("pin mismatch should fail with a network code, exit %d: %s", r.code, r.stderr)
	}
}

func TestCLI2_TOFUAcceptsAndPinsFingerprint(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	for _, tt := range []struct {
		name    string
		answer  string
		code    int
		pinned  bool
		message string
	}{
		{"yes pins the fingerprint", "y\n", 0, true, "Signed in"},
		{"no refuses", "n\n", 1, false, "CLI-NET-002"},
		{"empty answer refuses", "\n", 1, false, "CLI-NET-002"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfgHome := t.TempDir()
			env := map[string]string{"XDG_CONFIG_HOME": cfgHome}
			// No --pin here: the system does not trust the test certificate, so login must ask.
			var args []string
			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := writeFile(tokenFile, testToken); err != nil {
				t.Fatal(err)
			}
			args = []string{"login", "--token-file", tokenFile, "--server", h.srv.URL}
			r := runWith(t, env, tt.answer, args)
			if r.code != tt.code {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", r.code, tt.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, "SHA-256 fingerprint: "+h.pin) {
				t.Errorf("fingerprint not shown to user: %s", r.stderr)
			}
			if !strings.Contains(r.stdout+r.stderr, tt.message) {
				t.Errorf("output lacks %q: %s %s", tt.message, r.stdout, r.stderr)
			}
			cfg, found, _ := LoadConfig(filepath.Join(cfgHome, "nux", "config.json"))
			if tt.pinned != (found && cfg.Pin == h.pin) {
				t.Errorf("pinned = %v, config %+v found %v", tt.pinned, cfg, found)
			}
		})
	}
}

func TestCLI2_TelemetryPrintsPayloadExactly(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	r := h.nux(t, map[string]string{"NUX_TOKEN": testToken}, "", h.args("telemetry", "show")...)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, r.stdout)
	}
	if got["install_id"] != "i1" || got["schema_version"] != float64(1) {
		t.Errorf("payload altered: %v", got)
	}
	if !strings.Contains(h.lastPath(), "/api/v1/telemetry/preview") {
		t.Errorf("wrong endpoint %s", h.lastPath())
	}
}

func (h *harness) lastPath() string {
	seen := h.requests()
	if len(seen) == 0 {
		return ""
	}
	return seen[len(seen)-1].URL.Path
}

func TestCLI2_RequestsCarryBearerOnly(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	_ = h.nux(t, map[string]string{"NUX_TOKEN": testToken}, "", h.args("hosts", "ls")...)
	seen := h.requests()
	if len(seen) == 0 {
		t.Fatal("no request reached the server")
	}
	req := seen[0]
	if req.Header.Get("Authorization") != "Bearer "+testToken {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("Cookie") != "" {
		t.Error("CLI must not send cookies")
	}
}

func TestCLI2_ListCursorPassedThrough(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = h.defaultRoutes()
	_ = h.nux(t, map[string]string{"NUX_TOKEN": testToken}, "", h.args("hosts", "ls", "--cursor", "cursor-2", "--limit", "10")...)
	seen := h.requests()
	q := seen[0].URL.Query()
	if q.Get("cursor") != "cursor-2" || q.Get("limit") != "10" {
		t.Errorf("query = %s", seen[0].URL.RawQuery)
	}
}

func TestCLI2_ServerErrorNeverLeaksToken(t *testing.T) {
	// A server that echoes the request back in an error must not cause the token to show up in
	// the CLI output, because the CLI never copies request headers into messages.
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/v1/hosts": func(w http.ResponseWriter, _ *http.Request) {
			writeErr(w, http.StatusInternalServerError, "API-INT-001", "boom", "Try again.")
		},
	})
	r := h.nux(t, map[string]string{"NUX_TOKEN": testToken}, "", h.args("hosts", "ls")...)
	if strings.Contains(r.stdout+r.stderr, testToken) {
		t.Fatalf("token leaked:\n%s%s", r.stdout, r.stderr)
	}
	if r.code != 1 {
		t.Errorf("exit = %d, want 1", r.code)
	}
}

func writeFile(path, data string) error {
	return os.WriteFile(path, []byte(data), 0o600)
}

func chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func pinFromCert(raw []byte) string {
	return formatFingerprint(sha256.Sum256(raw))
}
