// SPDX-License-Identifier: Apache-2.0

// Package checks runs uptime checks that nuxd asks this agent to run from inside its network
// (UPT-2). The agent only probes outward: nothing here changes the host or a container
// (ADR-010). Probes are the shared ones of pkg/probe, under the agent policy: private ranges
// and loopback are reachable, link-local addresses (cloud metadata) are not.
package checks

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Limits on what the agent accepts from the server.
const (
	DefaultConcurrent = 8
	MinTimeout        = time.Second
	MaxTimeout        = 60 * time.Second
	maxHeaders        = 20
	maxURL            = 2048
	maxBody           = 8 << 10
	outBuffer         = 64
	// SockguardPath is the agent's only route to the container runtime; checks may never name it.
	SockguardPath = "/run/nux/sockguard.sock"
)

// Manager executes RunCheck requests with bounded concurrency; it implements run.Checks.
type Manager struct {
	log    *slog.Logger
	runner *probe.Runner
	sem    chan struct{}
	out    chan *agentv1.AgentMessage
	wg     sync.WaitGroup
	now    func() time.Time
}

// New builds a Manager running at most concurrent checks at once (0 means the default).
func New(log *slog.Logger, concurrent int) *Manager {
	if concurrent <= 0 {
		concurrent = DefaultConcurrent
	}
	return &Manager{
		log: log, runner: &probe.Runner{Policy: probe.AgentPolicy()}, sem: make(chan struct{}, concurrent),
		out: make(chan *agentv1.AgentMessage, outBuffer), now: time.Now,
	}
}

// Out yields CheckResult messages.
func (m *Manager) Out() <-chan *agentv1.AgentMessage { return m.out }

// Run starts rc if a worker is free and never blocks the stream loop. When none is free it
// answers at once with CHK-RUN-002 and no status, which the server records as unknown.
func (m *Manager) Run(ctx context.Context, rc *agentv1.RunCheck) {
	spec, err := Validate(rc)
	if err != nil {
		m.refuse(ctx, rc, errcode.CHKRun003)
		return
	}
	select {
	case m.sem <- struct{}{}:
	default:
		m.refuse(ctx, rc, errcode.CHKRun002)
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() { <-m.sem }()
		start := m.now()
		res := m.runner.Run(ctx, spec)
		m.reply(ctx, rc, res, start)
	}()
}

// refuse answers without a status, which the server records as unknown rather than down.
func (m *Manager) refuse(ctx context.Context, rc *agentv1.RunCheck, code errcode.Code) {
	m.send(ctx, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_CheckResult{CheckResult: &agentv1.CheckResult{
		CheckId: rc.GetCheckId(), RunId: rc.GetRunId(), ErrorCode: string(code), StartedAtUnixMs: m.now().UnixMilli(),
	}}})
}

func (m *Manager) reply(ctx context.Context, rc *agentv1.RunCheck, res probe.Result, start time.Time) {
	st := agentv1.CheckResult_STATUS_DOWN
	if res.Status == probe.StatusUp {
		st = agentv1.CheckResult_STATUS_UP
	}
	m.send(ctx, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_CheckResult{CheckResult: &agentv1.CheckResult{
		CheckId: rc.GetCheckId(), RunId: rc.GetRunId(), Status: st, StartedAtUnixMs: start.UnixMilli(),
		LatencyMs: uint32(min(res.Latency.Milliseconds(), 600_000)), //nolint:gosec // clamped
		ErrorCode: string(res.Code), Detail: res.Detail,
	}}})
}

func (m *Manager) send(ctx context.Context, msg *agentv1.AgentMessage) {
	select {
	case m.out <- msg:
	case <-ctx.Done():
	}
}

// CloseAll waits for running checks, which end promptly because the stream's context is cancelled.
func (m *Manager) CloseAll() { m.wg.Wait() }

// Validate converts and bounds a request. The server is authenticated but its messages are
// validated like any other input.
func Validate(rc *agentv1.RunCheck) (probe.Spec, error) {
	if rc.GetCheckId() == "" || rc.GetRunId() == "" {
		return probe.Spec{}, errors.New("missing ids")
	}
	spec, err := probe.FromProto(rc)
	if err != nil {
		return probe.Spec{}, err
	}
	spec.Timeout = min(max(spec.Timeout, MinTimeout), MaxTimeout)
	switch {
	case spec.HTTP != nil:
		h := spec.HTTP
		u, err := url.Parse(h.URL)
		if err != nil || len(h.URL) > maxURL || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return probe.Spec{}, errors.New("bad url")
		}
		if len(h.Headers) > maxHeaders || len(h.Body) > maxBody || len(h.ExpectedStatus) > 20 {
			return probe.Spec{}, errors.New("request too large")
		}
		for k, v := range h.Headers {
			if strings.ContainsAny(k, "\r\n\x00:") || strings.ContainsAny(v, "\r\n\x00") {
				return probe.Spec{}, errors.New("bad header")
			}
		}
		if h.MaxBodyBytes <= 0 {
			h.MaxBodyBytes = probe.DefaultMaxBodyBytes
		}
	case spec.TCP != nil:
		return spec, hostOK(spec.TCP.Host)
	case spec.TLS != nil:
		return spec, hostOK(spec.TLS.Host)
	case spec.Ping != nil:
		return spec, hostOK(spec.Ping.Host)
	case spec.DNS != nil:
		return spec, hostOK(spec.DNS.Name)
	}
	return spec, nil
}

// hostOK refuses anything that is not a plain host name or address, which in particular
// keeps the sockguard socket path out of reach.
func hostOK(h string) error {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "/\\ \x00") || strings.Contains(h, SockguardPath) {
		return errors.New("bad host")
	}
	return nil
}
