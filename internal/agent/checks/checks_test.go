// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

func newManager(concurrent int) *Manager {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), concurrent)
}

func tcpRun(runID, host string, port uint32) *agentv1.RunCheck {
	return &agentv1.RunCheck{CheckId: "chk1", RunId: runID, TimeoutMs: 2000, Spec: &agentv1.RunCheck_Tcp{Tcp: &agentv1.TcpCheck{Host: host, Port: port}}}
}

func httpRun(runID, url string) *agentv1.RunCheck {
	return &agentv1.RunCheck{CheckId: "chk1", RunId: runID, TimeoutMs: 2000, Spec: &agentv1.RunCheck_Http{Http: &agentv1.HttpCheck{Url: url}}}
}

func next(t *testing.T, m *Manager) *agentv1.CheckResult {
	t.Helper()
	select {
	case msg := <-m.Out():
		return msg.GetCheckResult()
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
		return nil
	}
}

func TestUPT2_AgentRunsTheSharedProbesAndEchoesTheRunID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := uint32(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a port number
	m := newManager(0)
	ctx := context.Background()

	m.Run(ctx, tcpRun("run-1", "127.0.0.1", port))
	if r := next(t, m); r.GetStatus() != agentv1.CheckResult_STATUS_UP || r.GetRunId() != "run-1" || r.GetCheckId() != "chk1" || r.GetStartedAtUnixMs() == 0 {
		t.Fatalf("result = %v", r)
	}
	_ = ln.Close()
	m.Run(ctx, tcpRun("run-2", "127.0.0.1", port))
	if r := next(t, m); r.GetStatus() != agentv1.CheckResult_STATUS_DOWN || r.GetErrorCode() != string(errcode.CHKTCP001) || r.GetRunId() != "run-2" {
		t.Fatalf("result = %v", r)
	}
	m.CloseAll()
}

func TestUPT2_AgentReachesPrivateTargetsButNotTheMetadataAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	m := newManager(0)
	m.Run(context.Background(), httpRun("r1", srv.URL))
	if r := next(t, m); r.GetStatus() != agentv1.CheckResult_STATUS_UP {
		t.Fatalf("loopback target = %v", r)
	}
	m.Run(context.Background(), httpRun("r2", "http://169.254.169.254/latest/meta-data/"))
	if r := next(t, m); r.GetStatus() != agentv1.CheckResult_STATUS_DOWN || r.GetErrorCode() != string(errcode.CHKNet001) {
		t.Fatalf("metadata = %v", r)
	}
	m.Run(context.Background(), tcpRun("r3", "169.254.169.254", 80))
	if r := next(t, m); r.GetErrorCode() != string(errcode.CHKNet001) {
		t.Fatalf("metadata tcp = %v", r)
	}
	m.CloseAll()
}

func TestUPT2_RequestsAreValidatedAndRefusedWithoutAStatus(t *testing.T) {
	m := newManager(0)
	hdr := func(k, v string) *agentv1.RunCheck {
		rc := httpRun("r", "http://example.com/")
		rc.GetHttp().Headers = map[string]string{k: v}
		return rc
	}
	for name, rc := range map[string]*agentv1.RunCheck{
		"sockguard path as host": tcpRun("r", SockguardPath, 80),
		"path in host":           tcpRun("r", "a/b", 80),
		"no run id":              tcpRun("", "example.com", 80),
		"no spec":                {CheckId: "c", RunId: "r"},
		"ftp scheme":             httpRun("r", "ftp://example.com/"),
		"userinfo":               httpRun("r", "http://u:p@example.com/"),
		"CRLF in header value":   hdr("X-A", "a\r\nX-B: c"),
		"colon in header name":   hdr("X:A", "a"),
		"too many headers": func() *agentv1.RunCheck {
			rc := httpRun("r", "http://example.com/")
			rc.GetHttp().Headers = map[string]string{}
			for i := range 21 {
				rc.GetHttp().Headers[strings.Repeat("h", i+1)] = "v"
			}
			return rc
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			m.Run(context.Background(), rc)
			r := next(t, m)
			if r.GetStatus() != agentv1.CheckResult_STATUS_UNSPECIFIED || r.GetErrorCode() != string(errcode.CHKRun003) {
				t.Fatalf("result = %v", r)
			}
		})
	}
}

func TestUPT2_TimeoutsAreClamped(t *testing.T) {
	for in, want := range map[uint32]time.Duration{0: MinTimeout, 100: MinTimeout, 5000: 5 * time.Second, 600000: MaxTimeout} {
		rc := tcpRun("r", "example.com", 80)
		rc.TimeoutMs = in
		spec, err := Validate(rc)
		if err != nil || spec.Timeout != want {
			t.Errorf("timeout %d -> %v, %v; want %v", in, spec.Timeout, err, want)
		}
	}
}

func TestUPT2_ABusyAgentAnswersWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	m := newManager(1)
	ctx, cancel := context.WithCancel(context.Background())
	m.Run(ctx, httpRun("slow", srv.URL))
	m.Run(ctx, httpRun("second", srv.URL)) // no free worker
	r := next(t, m)
	if r.GetRunId() != "second" || r.GetStatus() != agentv1.CheckResult_STATUS_UNSPECIFIED || r.GetErrorCode() != string(errcode.CHKRun002) {
		t.Fatalf("busy answer = %v", r)
	}
	close(release)
	if r := next(t, m); r.GetRunId() != "slow" || r.GetStatus() != agentv1.CheckResult_STATUS_UP {
		t.Fatalf("slow = %v", r)
	}
	cancel()
	m.CloseAll()
}

func TestUPT2_CancellingTheStreamStopsRunningChecks(_ *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	m := newManager(0)
	ctx, cancel := context.WithCancel(context.Background())
	m.Run(ctx, httpRun("r", srv.URL))
	cancel()
	m.CloseAll() // returns because the probe honours the context
}
