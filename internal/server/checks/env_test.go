// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return ctx.Err()
}

type fakeAgents struct {
	mu     sync.Mutex
	agents map[string]gateway.AgentInfo
}

func (f *fakeAgents) AgentByID(_ context.Context, id string) (gateway.AgentInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.agents[id]; ok {
		return a, nil
	}
	return gateway.AgentInfo{}, gateway.ErrAgentNotFound
}

type fakeSender struct {
	mu   sync.Mutex
	err  error
	sent chan sentMsg
}

type sentMsg struct {
	agentID string
	run     *agentv1.RunCheck
}

func (f *fakeSender) SendToAgent(agentID string, m *agentv1.ServerMessage) error {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return err
	}
	f.sent <- sentMsg{agentID, m.GetRunCheck()}
	return nil
}

func (f *fakeSender) fail(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// execLog records the specs a fake probe saw and answers from a queue (the last answer repeats).
type execLog struct {
	mu      sync.Mutex
	specs   []probe.Spec
	policy  []probe.Policy
	answers []probe.Result
}

func (e *execLog) exec(_ context.Context, p probe.Policy, s probe.Spec) probe.Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.specs = append(e.specs, s)
	e.policy = append(e.policy, p)
	i := min(len(e.specs)-1, len(e.answers)-1)
	return e.answers[i]
}

func (e *execLog) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.specs)
}

var (
	upResult   = probe.Result{Status: probe.StatusUp, Latency: 12 * time.Millisecond}
	downResult = probe.Result{Status: probe.StatusDown, Latency: 3 * time.Millisecond, Code: "CHK-HTTP-002", Detail: "status 503"}
)

type env struct {
	t      *testing.T
	svc    *Service
	db     *store.Store
	clock  *fakeClock
	agents *fakeAgents
	sender *fakeSender
	exec   *execLog
	logs   *bytes.Buffer
	dir    string
}

func newEnv(t *testing.T, mut ...func(*Options)) *env {
	t.Helper()
	dir := t.TempDir()
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	db, err := store.Open(context.Background(), dir, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		t: t, db: db, dir: dir, logs: logs,
		clock:  &fakeClock{now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)},
		agents: &fakeAgents{agents: map[string]gateway.AgentInfo{}},
		sender: &fakeSender{sent: make(chan sentMsg, 16)},
		exec:   &execLog{answers: []probe.Result{upResult}},
	}
	o := Options{DB: db, Secrets: box, Agents: e.agents, Sender: e.sender, Log: log, Clock: e.clock, Inline: true, Exec: e.exec.exec}
	for _, m := range mut {
		m(&o)
	}
	e.svc = New(o)
	return e
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

var who = Actor{UserID: "01USER", IP: "203.0.113.5"}

func tcpCheck(name string) Check {
	return Check{Name: name, Type: probe.TypeTCP, IntervalS: 60, TimeoutS: 5, Enabled: true, TCP: &TCPConfig{Host: "db.example.com", Port: 5432}}
}

func httpCheck(url string) Check {
	return Check{Name: "web", Type: probe.TypeHTTP, IntervalS: 60, TimeoutS: 5, Enabled: true, HTTP: &HTTPConfig{URL: url}}
}

func (e *env) create(c Check) View {
	e.t.Helper()
	v, err := e.svc.Create(context.Background(), c, who)
	if err != nil {
		e.t.Fatalf("create: %v", err)
	}
	return v
}

// dump returns every row of every table as text, to prove a plaintext appears nowhere.
func (e *env) dump() string {
	e.t.Helper()
	var sb strings.Builder
	for _, table := range []string{"checks", "check_state", "check_results", "check_rollups_daily", "secrets", "audit_log"} {
		rows, err := e.db.DB().Query(`SELECT * FROM ` + table)
		if err != nil {
			e.t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				e.t.Fatal(err)
			}
			for _, v := range vals {
				switch x := v.(type) {
				case []byte:
					sb.Write(x)
				case nil:
				default:
					sb.WriteString(strings.TrimSpace(strings.ReplaceAll(sqlString(x), "\n", " ")))
				}
				sb.WriteByte('|')
			}
			sb.WriteByte('\n')
		}
		_ = rows.Close()
	}
	return sb.String()
}

func sqlString(v any) string {
	var n sql.NullString
	_ = n.Scan(v)
	return n.String
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.DB().QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}
