// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	startTimeout = 30 * time.Second
	stopTimeout  = 30 * time.Second
)

// nuxdServer is a nuxd child process with its own data directory and loopback ports.
type nuxdServer struct {
	binary  string
	env     []string
	cmd     *exec.Cmd
	logFile *os.File
	BaseURL string
	// Pid is what /proc is sampled for.
	Pid int
}

type serverOptions struct {
	Binary     string
	WorkDir    string
	GOMAXPROCS int
}

// startNuxd launches nuxd on free loopback ports and waits until its health endpoint answers.
// Only loopback is used, and the check policy is relaxed so server-run checks may target the
// harness's own listener; both are needed for the load and not safe defaults for a real host.
func startNuxd(ctx context.Context, opt serverOptions) (*nuxdServer, error) {
	ports, err := freePorts(3)
	if err != nil {
		return nil, err
	}
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", ports[0])
	gatewayAddr := fmt.Sprintf("127.0.0.1:%d", ports[1])
	dataDir := filepath.Join(opt.WorkDir, "nuxd-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}

	env := childEnv(map[string]string{
		"NUXD_DATA_DIR":             dataDir,
		"NUXD_HTTPS_ADDR":           httpsAddr,
		"NUXD_REDIRECT_ADDR":        fmt.Sprintf("127.0.0.1:%d", ports[2]),
		"NUXD_GATEWAY_ADDR":         gatewayAddr,
		"NUXD_GATEWAY_PUBLIC_URL":   "https://" + gatewayAddr,
		"NUXD_PUBLIC_URL":           "https://" + httpsAddr,
		"NUXD_CHECKS_BLOCK_PRIVATE": "false",
		"NUXD_LOG_LEVEL":            "warn",
		"GOMAXPROCS":                fmt.Sprint(opt.GOMAXPROCS),
	})
	logFile, err := os.Create(filepath.Join(opt.WorkDir, "nuxd.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(opt.Binary) //nolint:gosec // the harness runs the binary the operator names with --nuxd
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start nuxd: %w", err)
	}
	s := &nuxdServer{binary: opt.Binary, env: env, cmd: cmd, logFile: logFile, BaseURL: "https://" + httpsAddr, Pid: cmd.Process.Pid}
	if err := s.awaitHealthy(ctx); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

func (s *nuxdServer) awaitHealthy(ctx context.Context) error {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // readiness probe of the self-signed loopback listener
	}}
	deadline := time.Now().Add(startTimeout)
	for {
		resp, err := client.Get(s.BaseURL + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("nuxd did not become healthy; see nuxd.log in the work directory")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// SetupToken runs `nuxd setup-token`, the same way an operator would, and returns the first-run secret.
func (s *nuxdServer) SetupToken(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, s.binary, "setup-token") //nolint:gosec // same binary as the server
	cmd.Env = s.env
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nuxd setup-token: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Stop asks nuxd to shut down, kills it if it does not, and closes the log.
func (s *nuxdServer) Stop() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = s.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(stopTimeout):
			_ = s.cmd.Process.Kill()
			<-done
		}
	}
	_ = s.logFile.Close()
}

// childEnv is the harness environment with any inherited NUXD_* settings removed, so a
// developer's shell cannot change what the load test measures.
func childEnv(overrides map[string]string) []string {
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(key, "NUXD_") || key == "GOMAXPROCS" {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

// freePorts reserves n loopback ports by binding and releasing them. There is a small window in
// which another process could take one; the harness fails fast if that happens.
func freePorts(n int) ([]int, error) {
	ports := make([]int, 0, n)
	for range n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		_ = ln.Close()
	}
	return ports, nil
}
