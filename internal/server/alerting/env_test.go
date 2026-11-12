// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"crypto/rand"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeChecks struct {
	mu     sync.Mutex
	states []checks.State
	hub    *checks.Hub
}

func (f *fakeChecks) States(context.Context) ([]checks.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]checks.State(nil), f.states...), nil
}
func (f *fakeChecks) Hub() *checks.Hub { return f.hub }

func (f *fakeChecks) set(id, name, state, detail, code string, since time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := checks.State{CheckID: id, Name: name, Enabled: true, Status: checks.Status{State: state, Since: &since, LastDetail: detail, LastErrorCode: code}}
	for i := range f.states {
		if f.states[i].CheckID == id {
			f.states[i] = st
			return
		}
	}
	f.states = append(f.states, st)
}

type fakeInv struct {
	mu    sync.Mutex
	hosts []inventory.Host
	ctrs  []inventory.Container
	hub   *inventory.Hub
}

func (f *fakeInv) Hosts() []inventory.Host {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inventory.Host(nil), f.hosts...)
}

func (f *fakeInv) Containers() []inventory.Container {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inventory.Container(nil), f.ctrs...)
}

func (f *fakeInv) Host(id string) (inventory.Host, bool) {
	for _, h := range f.Hosts() {
		if h.ID == id {
			return h, true
		}
	}
	return inventory.Host{}, false
}

func (f *fakeInv) Container(id string) (inventory.Container, bool) {
	for _, c := range f.Containers() {
		if c.ID == id {
			return c, true
		}
	}
	return inventory.Container{}, false
}
func (f *fakeInv) Subscribe() (*inventory.Subscription, error) { return f.hub.Subscribe() }

func (f *fakeInv) setHost(h inventory.Host) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.hosts {
		if f.hosts[i].ID == h.ID {
			f.hosts[i] = h
			return
		}
	}
	f.hosts = append(f.hosts, h)
}

func (f *fakeInv) setContainer(c inventory.Container) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.ctrs {
		if f.ctrs[i].ID == c.ID {
			f.ctrs[i] = c
			return
		}
	}
	f.ctrs = append(f.ctrs, c)
}

type fakeMetrics struct {
	mu  sync.Mutex
	rep metrics.PressureReport
	err error
}

func (f *fakeMetrics) Pressure(context.Context, int) (metrics.PressureReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rep, f.err
}

func (f *fakeMetrics) setHost(id string, cpu, mem, disk *float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rep.Hosts = []metrics.Pressure{{ID: id, CPUPercent: cpu, MemoryPercent: mem, DiskPercent: disk}}
}

func pct(v float64) *float64 { return &v }

type sent struct {
	channel string
	msg     notify.Message
}

type fakeSink struct {
	mu   sync.Mutex
	got  []sent
	full bool
}

func (s *fakeSink) Enqueue(ch string, m notify.Message) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.full {
		return false
	}
	s.got = append(s.got, sent{ch, m})
	return true
}

func (s *fakeSink) all() []sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sent(nil), s.got...)
}

func (s *fakeSink) kinds() []string {
	var out []string
	for _, x := range s.all() {
		out = append(out, x.msg.Kind)
	}
	return out
}

func (s *fakeSink) reset() {
	s.mu.Lock()
	s.got = nil
	s.mu.Unlock()
}

type env struct {
	t        *testing.T
	db       *store.Store
	box      *secrets.Box
	clock    *fakeClock
	checks   *fakeChecks
	inv      *fakeInv
	metrics  *fakeMetrics
	sink     *fakeSink
	svc      *Service
	channels *Channels
	who      Actor
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(context.Background(), t.TempDir(), slog.New(slog.DiscardHandler))
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
		t: t, db: db, box: box, clock: &fakeClock{t: t0}, checks: &fakeChecks{hub: checks.NewHub()}, inv: &fakeInv{hub: inventory.NewHub()},
		metrics: &fakeMetrics{}, sink: &fakeSink{}, who: Actor{UserID: "01USER", IP: "203.0.113.5"},
	}
	// Tests with hosts must not see the default rules unless they ask for them.
	if _, err := db.DB().Exec(`INSERT INTO alerting_state (key, value) VALUES ('defaults_seeded', '1')`); err != nil {
		t.Fatal(err)
	}
	e.svc = e.newService()
	e.channels = NewChannels(ChannelOptions{DB: db, Secrets: box, Sender: notify.NewSender(notify.Options{}), Now: e.clock.Now})
	return e
}

func (e *env) newService() *Service {
	return New(Options{
		DB: e.db, Checks: e.checks, Inventory: e.inv, Metrics: e.metrics, Sink: e.sink, Now: e.clock.Now,
		PublicURL: "https://nux.example.com/", RepeatInterval: time.Hour,
	})
}

func (e *env) eval() {
	e.t.Helper()
	if err := e.svc.Evaluate(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// step advances the clock one evaluation period and evaluates.
func (e *env) step(d time.Duration) {
	e.t.Helper()
	e.clock.Advance(d)
	e.eval()
}

func (e *env) rule(name, kind, severity, params string, sel Selector) Rule {
	e.t.Helper()
	r, err := e.svc.CreateRule(context.Background(), Rule{Name: name, Kind: kind, Severity: severity, Enabled: true, Selector: sel, Params: []byte(params)}, e.who)
	if err != nil {
		e.t.Fatalf("create rule %s: %v", name, err)
	}
	return r
}

func (e *env) channel(name string) Channel {
	e.t.Helper()
	ch, err := e.channels.Create(context.Background(), Channel{Name: name, Type: "slack", Enabled: true, Config: []byte(`{"url":"https://hooks.slack.com/services/T0/B0/SECRET-WEBHOOK"}`)}, e.who)
	if err != nil {
		e.t.Fatal(err)
	}
	return ch
}

func (e *env) routeAll(channelIDs ...string) {
	e.t.Helper()
	var rs []Route
	for _, c := range channelIDs {
		rs = append(rs, Route{ChannelID: c, Continue: true})
	}
	cur, _ := e.svc.Routes(context.Background())
	if _, err := e.svc.ReplaceRoutes(context.Background(), cur.ETag(), rs, e.who); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) alerts(state string) []Alert {
	e.t.Helper()
	items, _, err := e.svc.ListAlerts(context.Background(), AlertFilter{State: state}, "", 100)
	if err != nil {
		e.t.Fatal(err)
	}
	return items
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.DB().QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func newID(t *testing.T) string {
	t.Helper()
	id, err := ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func host(id, name, status string, tags map[string]string, seen time.Time) inventory.Host {
	return inventory.Host{ID: id, AgentID: "agent-" + id, Hostname: name, Status: status, Tags: tags, LastSeenAt: seen, MemoryBytes: 1 << 30, CPUCount: 4}
}
