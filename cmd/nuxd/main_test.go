// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

func TestVersionFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &out, &errOut, func(string) string { return "" }); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "nuxd ") {
		t.Errorf("output = %q", out.String())
	}
}

func TestBadFlagExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"--nope"}, &out, &errOut, func(string) string { return "" }); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestExplicitMissingConfigFails(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"--config", filepath.Join(t.TempDir(), "absent.yaml")}
	if code := run(context.Background(), args, &out, &errOut, func(string) string { return "" }); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), string(errcode.SRVCfg001)) {
		t.Errorf("stderr lacks %s: %q", errcode.SRVCfg001, errOut.String())
	}
}

// TestStartsServesAndStops runs the whole server against a temporary data
// directory and checks it answers over HTTPS, then shuts down on cancel.
func TestStartsServesAndStops(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "nuxd.yaml")
	body := "data_dir: " + filepath.Join(dir, "data") + "\nhttp:\n  https_addr: \"127.0.0.1:0\"\n  redirect_addr: \"127.0.0.1:0\"\nlog:\n  level: debug\n"
	if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var logs syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--config", cfgFile}, &bytes.Buffer{}, &logs, func(string) string { return "" })
	}()

	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, rest, ok := strings.Cut(logs.String(), `"https_addr":"`); ok {
			addr, _, _ = strings.Cut(rest, `"`)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("server did not start; logs: %s", logs.String())
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // self-signed certificate under test
	resp, err := client.Get("https://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/readyz = %d", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit = %d; logs: %s", code, logs.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("did not stop after cancel")
	}
	if strings.Contains(logs.String(), "secret") {
		t.Error("logs mention secrets")
	}
}

func TestSetupTokenCommand(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "nuxd.yaml")
	if err := os.WriteFile(cfgFile, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noEnv := func(string) string { return "" }

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"setup-token", "--config", cfgFile}, &out, &errOut, noEnv); code != 1 || !strings.Contains(errOut.String(), string(errcode.AuthSetup002)) {
		t.Errorf("without a token: exit %d, stderr %q", code, errOut.String())
	}

	if err := auth.NewSetupToken(dir).Ensure(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"setup-token", "--config", cfgFile}, &out, &errOut, noEnv); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	if got := strings.TrimSpace(out.String()); len(got) != 32 {
		t.Errorf("printed %q, want a 32-character token", got)
	}
}

func TestFirstRunCreatesTokenButNeverLogsIt(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "nuxd.yaml")
	body := "data_dir: " + filepath.Join(dir, "data") + "\nhttp:\n  https_addr: \"127.0.0.1:0\"\n  redirect_addr: \"127.0.0.1:0\"\n"
	if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var logs syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--config", cfgFile}, &bytes.Buffer{}, &logs, func(string) string { return "" })
	}()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), "nuxd started") {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	tokenFile := filepath.Join(dir, "data", "setup-token")
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("no setup token after first start: %v\n%s", err, logs.String())
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %o, want 600", info.Mode().Perm())
	}
	token, _ := auth.NewSetupToken(filepath.Join(dir, "data")).Read()
	if strings.Contains(logs.String(), token) {
		t.Error("the setup token must never appear in the logs")
	}
	if !strings.Contains(logs.String(), "nuxd setup-token") {
		t.Errorf("the log must tell the operator how to get the token: %s", logs.String())
	}
}
