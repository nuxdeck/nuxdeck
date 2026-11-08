// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Errors of RunNow.
var (
	ErrRateLimited = errors.New("check was run too recently")
)

// outcome is one finished run before it is recorded.
type outcome struct {
	status  string // up, down, unknown
	latency time.Duration
	code    errcode.Code
	detail  string
}

func fromProbe(r probe.Result) outcome {
	return outcome{status: string(r.Status), latency: r.Latency, code: r.Code, detail: r.Detail}
}

func unknown(code errcode.Code) outcome { return outcome{status: StateUnknown, code: code} }

// execute runs c, retrying a failed run up to retries more times; unknown results end it at once.
func (s *Service) execute(ctx context.Context, c Check, refs map[string]string, retries int) outcome {
	var out outcome
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			if err := s.clock.Sleep(ctx, s.RetryDelay); err != nil {
				return out
			}
		}
		out = s.attempt(ctx, c, refs)
		if out.status != StateDown {
			return out
		}
	}
	return out
}

func (s *Service) attempt(ctx context.Context, c Check, refs map[string]string) outcome {
	spec, err := s.buildSpec(ctx, c, refs)
	if err != nil {
		s.Log.Error("cannot read check credentials", "check_id", c.ID, "error", errcode.CodeOf(err))
		return unknown(errcode.CHKSec001)
	}
	if c.Runner == RunnerServer {
		p := probe.Policy{AllowPrivate: c.AllowPrivate && !s.BlockPrivate}
		if s.Policy != nil {
			p = s.Policy(c)
		}
		if s.Exec != nil {
			return fromProbe(s.Exec(ctx, p, spec))
		}
		r := probe.Runner{Policy: p, Now: s.clock.Now}
		return fromProbe(r.Run(ctx, spec))
	}
	return s.runOnAgent(ctx, c, spec)
}

// buildSpec turns a stored check into a probe spec, decrypting credentials just in time.
func (s *Service) buildSpec(ctx context.Context, c Check, refs map[string]string) (probe.Spec, error) {
	sp := probe.Spec{Type: c.Type, Timeout: time.Duration(c.TimeoutS) * time.Second}
	switch c.Type {
	case probe.TypeHTTP:
		h := c.HTTP
		out := &probe.HTTPSpec{
			URL: h.URL, Method: h.Method, Body: []byte(h.Body), ExpectedStatus: h.ExpectedStatus, Keyword: h.Keyword,
			VerifyTLS: h.VerifyTLS == nil || *h.VerifyTLS, MaxBodyBytes: h.MaxBodyBytes, Headers: map[string]string{},
		}
		if h.MaxRedirects != nil {
			out.MaxRedirects = *h.MaxRedirects
		}
		if h.JSON != nil {
			out.JSONPath, out.JSONOp, out.JSONValue = h.JSON.Path, h.JSON.Op, h.JSON.Value
		}
		get := func(key string) (string, error) {
			id, ok := refs[key]
			if !ok {
				return "", errcode.New(errcode.CHKSec001, "no secret for %s", key)
			}
			b, err := s.box.Get(ctx, s.db.DB(), id)
			if err != nil {
				return "", err
			}
			defer clear(b)
			return string(b), nil
		}
		for _, hd := range h.Headers {
			if !hd.Secret {
				out.Headers[hd.Name] = hd.Value
				continue
			}
			v, err := get("header:" + strings.ToLower(hd.Name))
			if err != nil {
				return probe.Spec{}, err
			}
			out.Headers[hd.Name] = v
		}
		if a := h.Auth; a != nil {
			switch a.Type {
			case "basic":
				pw, err := get("auth.password")
				if err != nil {
					return probe.Spec{}, err
				}
				out.Headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(a.Username+":"+pw))
			case "bearer":
				tok, err := get("auth.token")
				if err != nil {
					return probe.Spec{}, err
				}
				out.Headers["Authorization"] = "Bearer " + tok
			}
		}
		sp.HTTP = out
	case probe.TypeTCP:
		sp.TCP = &probe.TCPSpec{Host: c.TCP.Host, Port: c.TCP.Port}
	case probe.TypeDNS:
		sp.DNS = &probe.DNSSpec{Name: c.DNS.Name, RecordType: c.DNS.RecordType, Resolver: c.DNS.Resolver, Expected: c.DNS.Expected}
	case probe.TypeTLS:
		t := c.TLS
		sp.TLS = &probe.TLSSpec{Host: t.Host, Port: t.Port, ServerName: t.ServerName, WarnDays: derefInt(t.WarnDays), VerifyChain: t.VerifyChain == nil || *t.VerifyChain}
	case probe.TypePing:
		sp.Ping = &probe.PingSpec{Host: c.Ping.Host, Count: c.Ping.Count}
	}
	return sp, nil
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// pending is a RunCheck sent to an agent and not yet answered.
type pending struct {
	checkID, agentID string
	deadline         time.Time
	ch               chan outcome
}

func (s *Service) runOnAgent(ctx context.Context, c Check, spec probe.Spec) outcome {
	runID, err := ids.New()
	if err != nil {
		return unknown(errcode.CHKRun002)
	}
	p := &pending{checkID: c.ID, agentID: c.Runner, ch: make(chan outcome, 1), deadline: s.clock.Now().Add(spec.Timeout + pendingGrace)}
	s.mu.Lock()
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		return unknown(errcode.CHKRun002)
	}
	s.pending[runID] = p
	s.mu.Unlock()

	if s.Sender == nil {
		s.dropPending(runID)
		return unknown(errcode.CHKRun001)
	}
	msg := &agentv1.ServerMessage{Body: &agentv1.ServerMessage_RunCheck{RunCheck: probe.ToProto(c.ID, runID, spec)}}
	if err := s.Sender.SendToAgent(c.Runner, msg); err != nil {
		s.dropPending(runID)
		if errors.Is(err, gateway.ErrAgentBusy) {
			return unknown(errcode.CHKRun002)
		}
		return unknown(errcode.CHKRun001)
	}
	select {
	case out := <-p.ch:
		return out
	case <-ctx.Done():
		s.dropPending(runID)
		return unknown(errcode.CHKRun003)
	}
}

func (s *Service) dropPending(runID string) {
	s.mu.Lock()
	delete(s.pending, runID)
	s.mu.Unlock()
}

var codePattern = regexp.MustCompile(`^CHK-[A-Z]{3,4}-[0-9]{3}$`)

// HandleMessage consumes CheckResult messages. agentID comes from the agent's certificate. A
// result is accepted once, for a run this server sent to that very agent for that very check;
// anything else (unsolicited, duplicate, late, or for another agent's check) is dropped.
func (s *Service) HandleMessage(agentID string, m *agentv1.AgentMessage) {
	r := m.GetCheckResult()
	if r == nil {
		return
	}
	s.mu.Lock()
	p, ok := s.pending[r.GetRunId()]
	if !ok || p.agentID != agentID || p.checkID != r.GetCheckId() {
		s.ignoredMsgs++
		s.mu.Unlock()
		s.Log.Debug("ignored unmatched check result", "agent_id", agentID)
		return
	}
	delete(s.pending, r.GetRunId())
	s.mu.Unlock()

	out := outcome{latency: time.Duration(min(r.GetLatencyMs(), 600_000)) * time.Millisecond, detail: sanitizeDetail(r.GetDetail())}
	switch r.GetStatus() {
	case agentv1.CheckResult_STATUS_UP:
		out.status = StateUp
	case agentv1.CheckResult_STATUS_DOWN:
		out.status = StateDown
		out.code = errcode.Code(r.GetErrorCode())
		if !codePattern.MatchString(string(out.code)) {
			out.code = errcode.CHKRun003
		}
	default: // no status: the agent could not run it (busy, or it refused the request)
		code := errcode.Code(r.GetErrorCode())
		if code != errcode.CHKRun002 {
			code = errcode.CHKRun003
		}
		out = unknown(code)
	}
	p.ch <- out
}

// Ignored reports how many unmatched results were dropped.
func (s *Service) Ignored() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ignoredMsgs
}

func sanitizeDetail(d string) string {
	if len(d) > probe.MaxDetailBytes {
		d = d[:probe.MaxDetailBytes]
	}
	if !utf8.ValidString(d) {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, d)
}

// AgentGone ends every request waiting on agentID: it can no longer answer.
func (s *Service) AgentGone(agentID string) {
	s.mu.Lock()
	var gone []*pending
	for id, p := range s.pending {
		if p.agentID == agentID {
			gone = append(gone, p)
			delete(s.pending, id)
		}
	}
	s.mu.Unlock()
	for _, p := range gone {
		p.ch <- unknown(errcode.CHKRun001)
	}
}

func (s *Service) reapPending(now time.Time) {
	s.mu.Lock()
	var expired []*pending
	for id, p := range s.pending {
		if now.After(p.deadline) {
			expired = append(expired, p)
			delete(s.pending, id)
		}
	}
	s.mu.Unlock()
	for _, p := range expired {
		p.ch <- unknown(errcode.CHKRun003)
	}
}

// PendingCount reports unanswered agent requests; for tests and metrics.
func (s *Service) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// record stores a result and the new state in one transaction (with ev, when given) and
// publishes a state change afterwards.
func (s *Service) record(ctx context.Context, c Check, out outcome, ev *audit.Event) error {
	now := s.clock.Now().UTC()
	ms := out.latency.Milliseconds()
	var from string
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM checks WHERE id = ?`, c.ID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var since int64
		err := tx.QueryRowContext(ctx, `SELECT status, since_at FROM check_state WHERE check_id = ?`, c.ID).Scan(&from, &since)
		if errors.Is(err, sql.ErrNoRows) {
			from, since = StateUnknown, now.UnixMilli()
		} else if err != nil {
			return err
		}
		if from != out.status {
			since = now.UnixMilli()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO check_results (check_id, ts, status, latency_ms, error_code, detail) VALUES (?, ?, ?, ?, ?, ?)`,
			c.ID, now.UnixMilli(), out.status, ms, string(out.code), out.detail); err != nil {
			return fmt.Errorf("insert result: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO check_state (check_id, status, since_at, last_checked_at, last_latency_ms, last_error_code, last_detail) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (check_id) DO UPDATE SET status = excluded.status, since_at = excluded.since_at, last_checked_at = excluded.last_checked_at,
			last_latency_ms = excluded.last_latency_ms, last_error_code = excluded.last_error_code, last_detail = excluded.last_detail`,
			c.ID, out.status, since, now.UnixMilli(), ms, string(out.code), out.detail); err != nil {
			return fmt.Errorf("upsert state: %w", err)
		}
		if ev != nil {
			return s.db.AppendAudit(ctx, tx, *ev)
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) { // deleted while running: nothing to record
		return nil
	}
	if err != nil {
		return err
	}
	if from != out.status {
		s.hub.Publish(Event{CheckID: c.ID, Name: c.Name, From: from, To: out.status, At: now, LatencyMS: ms, ErrorCode: string(out.code), Detail: out.detail})
	}
	return nil
}

// RunNow runs a check once, immediately, and records the result with an audit entry. It does
// not retry. Calls closer together than ManualRunGap, or while the check is already running,
// are refused.
func (s *Service) RunNow(ctx context.Context, id string, who Actor) (Result, error) {
	c, refs, err := s.load(ctx, id)
	if err != nil {
		return Result{}, err
	}
	now := s.clock.Now()
	s.mu.Lock()
	if last, ok := s.lastManual[id]; (ok && now.Sub(last) < ManualRunGap) || s.running[id] {
		s.mu.Unlock()
		return Result{}, ErrRateLimited
	}
	s.lastManual[id] = now
	s.running[id] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, id)
		s.mu.Unlock()
	}()

	out := s.execute(ctx, c, refs, 0)
	ev := who.event("check.run", id, map[string]any{"status": out.status, "error_code": string(out.code)})
	if err := s.record(ctx, c, out, &ev); err != nil {
		return Result{}, err
	}
	return Result{TS: s.clock.Now().UTC(), Status: out.status, LatencyMS: out.latency.Milliseconds(), ErrorCode: string(out.code), Detail: out.detail}, nil
}
