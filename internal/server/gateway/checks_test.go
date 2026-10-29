// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentchecks "github.com/nuxdeck/nuxdeck/internal/agent/checks"
	"github.com/nuxdeck/nuxdeck/internal/agent/run"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// TestUPT2_AgentRunsACheckOverTheRealStream drives a real agent over the real mTLS gateway:
// the server sends RunCheck with a resolved secret, the agent probes a private target that
// only it can reach, and the CheckResult comes back and is recorded.
func TestUPT2_AgentRunsACheckOverTheRealStream(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(t.TempDir(), "state")
	agentID := e.enrollAgent(dir)

	var sawAuth atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "internal service ok")
	}))
	defer target.Close()

	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	clock := &stepClock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	svc := checks.New(checks.Options{DB: e.db, Secrets: box, Agents: e.db, Sender: e.gw, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Inline: true, Clock: clock})
	fn := func(id string, m *agentv1.AgentMessage) { svc.HandleMessage(id, m) }
	e.hook.Store(&fn)

	r := e.runAgent(dir, func(c *run.Config) { c.Checks = agentchecks.New(c.Log, 0) })
	defer r.stop()
	e.wantPresence(agentID, true, 5*time.Second)

	// 127.0.0.1 is not reachable for a server-run check; on the agent it is the point.
	c := checks.Check{Name: "internal", Type: probe.TypeHTTP, Runner: agentID, IntervalS: 60, TimeoutS: 5, Enabled: true, HTTP: &checks.HTTPConfig{
		URL: target.URL, Keyword: "ok", Auth: &checks.Auth{Type: "bearer", Token: &checks.Secret{Plain: new("e2e-secret")}},
	}}
	v, err := svc.Create(context.Background(), c, checks.Actor{UserID: "01ADMIN"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.RunNow(context.Background(), v.ID, checks.Actor{UserID: "01ADMIN"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != checks.StateUp {
		t.Fatalf("result = %+v", res)
	}
	if sawAuth.Load() != "Bearer e2e-secret" {
		t.Fatalf("target saw Authorization %v", sawAuth.Load())
	}

	// A failing target is reported as down with the probe's code, not unknown.
	target.Close()
	clock.pastRateLimit()
	svc2Res, err := svc.RunNow(context.Background(), v.ID, checks.Actor{UserID: "01ADMIN"})
	if err != nil {
		t.Fatal(err)
	}
	if svc2Res.Status != checks.StateDown || svc2Res.ErrorCode != "CHK-HTTP-001" {
		t.Fatalf("closed target = %+v", svc2Res)
	}

	// The agent goes away: the same check is unknown with a clear code, not down.
	r.stop()
	_ = r.wait(t, 5*time.Second)
	e.wantPresence(agentID, false, 5*time.Second)
	clock.pastRateLimit()
	res, err = svc.RunNow(context.Background(), v.ID, checks.Actor{UserID: "01ADMIN"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != checks.StateUnknown || res.ErrorCode != "CHK-RUN-001" {
		t.Fatalf("offline agent = %+v", res)
	}
}

// stepClock is a clock the test advances by hand.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return ctx.Err()
}

func (c *stepClock) pastRateLimit() {
	c.mu.Lock()
	c.t = c.t.Add(checks.ManualRunGap)
	c.mu.Unlock()
}
