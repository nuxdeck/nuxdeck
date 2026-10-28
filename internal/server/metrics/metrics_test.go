// SPDX-License-Identifier: AGPL-3.0-only

package metrics_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func (s *safeBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t   *testing.T
	svc *metrics.Service
	clk *clock
	log *safeBuf
	dir string
}

const nameLabel = "__name__"

const (
	hostA = "01HOSTAAAAAAAAAAAAAAAAAAAA"
	hostB = "01HOSTBBBBBBBBBBBBBBBBBBBB"
	ctrA  = "01CTRAAAAAAAAAAAAAAAAAAAAA"
	ctrB  = "01CTRBBBBBBBBBBBBBBBBBBBBB"
)

func testIndex() *inventory.Index {
	return inventory.NewIndex(
		[]inventory.Host{
			{ID: hostA, AgentID: "agent-a", Hostname: "alpha", CPUCount: 4, MemoryBytes: 1000, Status: inventory.StatusOnline},
			{ID: hostB, AgentID: "agent-b", Hostname: "beta", CPUCount: 2, MemoryBytes: 1000, Status: inventory.StatusOnline},
		},
		[]inventory.Container{
			{ID: ctrA, HostID: hostA, RuntimeID: "rid-a", Name: "web"},
			{ID: ctrB, HostID: hostB, RuntimeID: "rid-b", Name: "db"},
		})
}

func newEnvAt(t *testing.T, dir string, clk *clock, idx metrics.Inventory) *env {
	t.Helper()
	buf := &safeBuf{}
	svc, err := metrics.Open(metrics.Options{
		Dir: dir, Log: slog.New(slog.NewTextHandler(buf, nil)), Inventory: idx, Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return &env{t: t, svc: svc, clk: clk, log: buf, dir: dir}
}

func newEnv(t *testing.T) *env {
	// Aligned to 5 minutes so bucket arithmetic in tests is exact.
	clk := &clock{t: time.UnixMilli(1_900_000_000_000 - 1_900_000_000_000%300_000)}
	return newEnvAt(t, t.TempDir(), clk, testIndex())
}

func series(kind agentv1.TargetKind, id, metric string, lbl map[string]string, pts ...*agentv1.Point) *agentv1.Series {
	return &agentv1.Series{Target: &agentv1.Target{Kind: kind, Id: id}, Metric: metric, Labels: lbl, Points: pts}
}

func pt(ts time.Time, v float64) *agentv1.Point {
	return &agentv1.Point{TsUnixMs: ts.UnixMilli(), Value: v}
}

func (e *env) send(agent string, ss ...*agentv1.Series) {
	e.svc.HandleMessage(agent, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Metrics{Metrics: &agentv1.MetricBatch{Series: ss}}})
}

func (e *env) query(q metrics.Query) metrics.Result {
	e.t.Helper()
	r, err := e.svc.Query(context.Background(), q)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

const (
	host = agentv1.TargetKind_TARGET_KIND_HOST
	ctr  = agentv1.TargetKind_TARGET_KIND_CONTAINER
)

func TestIngestQueryRoundTrip(t *testing.T) { // MET-4, MET-6
	e := newEnv(t)
	now := e.clk.now()
	var pts []*agentv1.Point
	for i := 0; i < 10; i++ {
		pts = append(pts, pt(now.Add(-time.Duration(10-i)*15*time.Second), float64(i)))
	}
	e.send("agent-a",
		series(host, "", "nux_host_load_average", map[string]string{"window": "1m"}, pts...),
		series(ctr, "rid-a", "nux_container_cpu_usage_ratio", nil, pt(now.Add(-time.Minute), 0.5)))

	r := e.query(metrics.Query{
		TargetType: metrics.TargetHost, Target: hostA, Metric: "nux_host_load_average",
		From: now.Add(-time.Hour), To: now, Step: time.Second,
	})
	if r.Resolution != metrics.ResolutionFull || r.Kind != "gauge" || len(r.Series) != 1 || len(r.Series[0].Points) != 10 {
		t.Fatalf("unexpected result: %+v", r)
	}
	s := r.Series[0]
	if s.Labels["window"] != "1m" || s.Labels["target"] != hostA || s.Labels["target_type"] != "host" || s.Labels["__name__"] != "" {
		t.Fatalf("labels = %v", s.Labels)
	}
	if s.Points[3].Value != 3 {
		t.Fatalf("point 3 = %v", s.Points[3])
	}

	c := e.query(metrics.Query{TargetType: metrics.TargetContainer, Target: ctrA, Metric: "nux_container_cpu_usage_ratio", From: now.Add(-time.Hour), To: now})
	if len(c.Series) != 1 || c.Series[0].Labels["host"] != hostA || c.Series[0].Points[0].Value != 0.5 {
		t.Fatalf("container result: %+v", c)
	}
	if st := e.svc.Stats(); st.Accepted != 11 {
		t.Fatalf("accepted = %d", st.Accepted)
	}
}

func TestCounterQueryReturnsRate(t *testing.T) {
	e := newEnv(t)
	now := e.clk.now()
	var pts []*agentv1.Point
	for i := 0; i < 20; i++ { // +30 bytes every 15 s = 2 B/s, with a reset in the middle
		v := float64(i * 30)
		if i >= 10 {
			v = float64((i - 10) * 30)
		}
		pts = append(pts, pt(now.Add(-time.Duration(20-i)*15*time.Second), v))
	}
	e.send("agent-a", series(host, "", "nux_host_network_bytes_total", map[string]string{"interface": "eth0", "direction": "rx"}, pts...))
	r := e.query(metrics.Query{
		TargetType: metrics.TargetHost, Target: hostA, Metric: "nux_host_network_bytes_total",
		Labels: map[string]string{"direction": "rx"}, From: now.Add(-10 * time.Minute), To: now, Step: 15 * time.Second,
	})
	if r.Kind != "rate" || len(r.Series) != 1 {
		t.Fatalf("%+v", r)
	}
	for _, p := range r.Series[0].Points {
		if p.Value != 2 {
			t.Fatalf("rate = %v, want 2", p.Value)
		}
	}
	none := e.query(metrics.Query{
		TargetType: metrics.TargetHost, Target: hostA, Metric: "nux_host_network_bytes_total",
		Labels: map[string]string{"direction": "tx"}, From: now.Add(-10 * time.Minute), To: now,
	})
	if len(none.Series) != 0 {
		t.Fatal("label filter ignored")
	}
}

func TestPerAgentIsolation(t *testing.T) { // an agent cannot write another host's series
	e := newEnv(t)
	now := e.clk.now()
	p := pt(now.Add(-time.Second), 7)
	// Agent A names B's container runtime ID, and sends a host series: the host is A's own.
	e.send("agent-a",
		series(ctr, "rid-b", "nux_container_cpu_usage_ratio", nil, p),
		series(ctr, ctrB, "nux_container_cpu_usage_ratio", nil, p), // inventory ID instead of runtime ID
		series(host, hostB, "nux_host_load_average", map[string]string{"window": "1m"}, p))
	q := func(typ, id, metric string) int {
		return len(e.query(metrics.Query{TargetType: typ, Target: id, Metric: metric, From: now.Add(-time.Hour), To: now}).Series)
	}
	if q(metrics.TargetContainer, ctrB, "nux_container_cpu_usage_ratio") != 0 {
		t.Fatal("agent A wrote a series for B's container")
	}
	if q(metrics.TargetHost, hostB, "nux_host_load_average") != 0 {
		t.Fatal("agent A wrote a series for B's host")
	}
	if q(metrics.TargetHost, hostA, "nux_host_load_average") != 1 {
		t.Fatal("host target was not mapped to the authenticated agent's own host")
	}
	// An unknown agent (no inventory host) writes nothing.
	e.send("agent-ghost", series(host, "", "nux_host_load_average", map[string]string{"window": "5m"}, p))
	if st := e.svc.Stats(); st.Dropped["unknown_host"] != 1 || st.Dropped["unknown_target"] != 2 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestIngestRejectsBadData(t *testing.T) {
	e := newEnv(t)
	now := e.clk.now()
	ok := pt(now.Add(-time.Second), 1)
	long := strings.Repeat("x", 300)
	e.send("agent-a",
		series(host, "", "not_in_catalogue", nil, ok),
		series(host, "", "nux_container_cpu_usage_ratio", nil, ok),                       // container metric on host target
		series(host, "", "nux_host_load_average", map[string]string{"evil": "1"}, ok),    // label name not allowed
		series(host, "", "nux_host_load_average", map[string]string{"window": long}, ok), // value too long
		series(host, "", "nux_host_load_average", map[string]string{"window": "1m"},
			pt(now.Add(-2*time.Hour), 1), pt(now.Add(time.Hour), 1), // outside skew
			&agentv1.Point{TsUnixMs: now.UnixMilli(), Value: nanValue()}, ok),
		series(agentv1.TargetKind_TARGET_KIND_UNSPECIFIED, "", "nux_host_load_average", nil, ok))
	st := e.svc.Stats()
	want := map[string]uint64{"metric_not_allowed": 1, "unknown_target": 2, "labels_not_allowed": 2, "timestamp_out_of_range": 2, "invalid_value": 1}
	for k, v := range want {
		if st.Dropped[k] != v {
			t.Errorf("dropped[%s] = %d, want %d (all: %v)", k, st.Dropped[k], v, st.Dropped)
		}
	}
	if st.Accepted != 1 {
		t.Errorf("accepted = %d, want 1", st.Accepted)
	}
	// Warning logged once per agent and reason, not once per sample.
	for i := 0; i < 5; i++ {
		e.send("agent-a", series(host, "", "not_in_catalogue", nil, ok))
	}
	if n := strings.Count(e.log.String(), "reason=metric_not_allowed"); n != 1 {
		t.Errorf("warning logged %d times, want 1", n)
	}
}

func TestIngestBounds(t *testing.T) {
	e := newEnv(t)
	now := e.clk.now()
	var many []*agentv1.Point
	for i := 0; i < 1500; i++ {
		many = append(many, pt(now.Add(-time.Duration(i)*time.Millisecond), 1))
	}
	e.send("agent-a", series(host, "", "nux_host_load_average", map[string]string{"window": "1m"}, many...))
	if st := e.svc.Stats(); st.Accepted != 1000 || st.Dropped["batch_limit"] != 500 {
		t.Fatalf("stats = %+v", st)
	}
}

func nanValue() float64 { var z float64; return z / z }

func TestDownsampleCorrectnessIdempotencyAndResume(t *testing.T) { // MET-5
	e := newEnv(t)
	start := e.clk.now().Add(-3 * time.Hour) // 5-minute aligned
	lbl := map[string]string{"window": "1m"}
	ingestHistory(e, start, e.clk.now(), lbl)
	if err := e.svc.Downsample(context.Background()); err != nil {
		t.Fatal(err)
	}
	q := metrics.Query{TargetType: metrics.TargetHost, Target: hostA, Metric: "nux_host_load_average", From: start.Add(-47 * time.Hour), To: start.Add(2 * time.Hour), Step: 5 * time.Minute}
	first := e.query(q)
	if first.Resolution != metrics.Resolution5m || len(first.Series) != 1 {
		t.Fatalf("%+v", first)
	}
	// Bucket k covers seconds [300k, 300k+300): 20 samples at 15 s spacing, mean = 300k + 142.5.
	for k, p := range first.Series[0].Points {
		want := float64(300*k) + 142.5
		if p.Value != want || p.TS != start.UnixMilli()+int64(k)*300_000 {
			t.Fatalf("bucket %d = %+v, want value %v", k, p, want)
		}
	}
	if n := len(first.Series[0].Points); n < 20 {
		t.Fatalf("only %d buckets", n)
	}

	// Idempotent: a second run changes nothing; a forced rerun from scratch (watermark lost) also does not.
	if err := e.svc.Downsample(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSame(t, first, e.query(q))
	if err := e.svc.Close(); err != nil {
		t.Fatal(err)
	}
	removeWatermark(t, e.dir)
	e2 := newEnvAt(t, e.dir, e.clk, testIndex())
	if err := e2.svc.Downsample(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSame(t, first, e2.query(q))

	// Resumable: a new job run after more time only adds the newer buckets.
	e2.clk.add(time.Hour)
	if err := e2.svc.Downsample(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSame(t, first, e2.query(q))
}

// ingestHistory feeds samples through ingest by stepping the fake clock so each batch is "live".
func ingestHistory(e *env, from, to time.Time, lbl map[string]string) {
	saved := e.clk.now()
	defer func() { e.clk.mu.Lock(); e.clk.t = saved; e.clk.mu.Unlock() }()
	for ts := from; ts.Before(to); ts = ts.Add(15 * time.Second) {
		e.clk.mu.Lock()
		e.clk.t = ts.Add(time.Second)
		e.clk.mu.Unlock()
		e.send("agent-a", series(host, "", "nux_host_load_average", lbl, pt(ts, ts.Sub(from).Seconds())))
	}
}

func assertSame(t *testing.T, a, b metrics.Result) {
	t.Helper()
	if len(a.Series) != len(b.Series) || len(a.Series[0].Points) != len(b.Series[0].Points) {
		t.Fatalf("results differ: %d vs %d points", len(a.Series[0].Points), len(b.Series[0].Points))
	}
	for i := range a.Series[0].Points {
		if a.Series[0].Points[i] != b.Series[0].Points[i] {
			t.Fatalf("point %d differs: %v vs %v", i, a.Series[0].Points[i], b.Series[0].Points[i])
		}
	}
}

func TestQueryResolutionAndClamps(t *testing.T) { // MET-6
	e := newEnv(t)
	now := e.clk.now()
	base := metrics.Query{TargetType: metrics.TargetHost, Target: hostA, Metric: "nux_host_load_average", To: now}

	cases := []struct {
		name string
		from time.Duration
		step time.Duration
		res  string
		min  int64 // minimum effective step seconds
	}{
		{"1h", time.Hour, 0, metrics.ResolutionFull, 3},
		{"24h", 24 * time.Hour, 0, metrics.ResolutionFull, 86},
		{"7d uses averages", 7 * 24 * time.Hour, 0, metrics.Resolution5m, 300},
		{"20d uses averages", 20 * 24 * time.Hour, time.Second, metrics.Resolution5m, 300},
		{"tiny step is clamped to the point cap", 48 * time.Hour, time.Second, metrics.ResolutionFull, 16},
	}
	for _, c := range cases {
		q := base
		q.From, q.Step = now.Add(-c.from), c.step
		r := e.query(q)
		if r.Resolution != c.res || r.StepSeconds < c.min {
			t.Errorf("%s: resolution %s step %d, want %s step >= %d", c.name, r.Resolution, r.StepSeconds, c.res, c.min)
		}
		if pts := int64(c.from/time.Second) / r.StepSeconds; pts > metrics.MaxPointsPerSeries {
			t.Errorf("%s: %d points exceed the cap", c.name, pts)
		}
	}
}

func TestQueryValidation(t *testing.T) {
	e := newEnv(t)
	now := e.clk.now()
	ok := metrics.Query{TargetType: metrics.TargetHost, Target: hostA, Metric: "nux_host_load_average", From: now.Add(-time.Hour), To: now}
	bad := map[string]func(*metrics.Query){
		"metric":  func(q *metrics.Query) { q.Metric = "up{job='x'}" },
		"metric ": func(q *metrics.Query) { q.Metric = "nux_container_cpu_usage_ratio" }, // wrong target kind
		"to":      func(q *metrics.Query) { q.To = q.From },
		"from":    func(q *metrics.Query) { q.From = now.Add(-200 * 24 * time.Hour) },
		"step":    func(q *metrics.Query) { q.Step = -time.Second },
		"label":   func(q *metrics.Query) { q.Labels = map[string]string{"__name__": "x"} },
	}
	for field, mutate := range bad {
		q := ok
		mutate(&q)
		_, err := e.svc.Query(context.Background(), q)
		var inv *metrics.ErrInvalidQuery
		if !errors.As(err, &inv) || inv.Field != strings.TrimSpace(field) {
			t.Errorf("%s: err = %v", field, err)
		}
	}
}

func TestPressureRanking(t *testing.T) { // MET-7
	e := newEnv(t)
	now := e.clk.now().Add(-time.Second)
	e.send("agent-a",
		series(host, "", "nux_host_cpu_usage_ratio", map[string]string{"cpu": "all"}, pt(now, 0.25)),
		series(host, "", "nux_host_memory_bytes", map[string]string{"type": "used"}, pt(now, 900)),
		series(host, "", "nux_host_memory_bytes", map[string]string{"type": "total"}, pt(now, 1000)),
		series(host, "", "nux_host_filesystem_bytes", map[string]string{"mount": "/", "device": "sda", "fstype": "ext4", "type": "used"}, pt(now, 50)),
		series(host, "", "nux_host_filesystem_bytes", map[string]string{"mount": "/", "device": "sda", "fstype": "ext4", "type": "size"}, pt(now, 100)),
		series(ctr, "rid-a", "nux_container_cpu_usage_ratio", nil, pt(now, 2)), // 2 cores of 4
		series(ctr, "rid-a", "nux_container_memory_bytes", map[string]string{"type": "working_set"}, pt(now, 100)))
	e.send("agent-b",
		series(host, "", "nux_host_cpu_usage_ratio", map[string]string{"cpu": "all"}, pt(now, 0.95)),
		series(ctr, "rid-b", "nux_container_cpu_usage_ratio", nil, pt(now, 1.9)), // 95% of 2 cores
		series(ctr, "rid-b", "nux_container_memory_bytes", map[string]string{"type": "usage"}, pt(now, 800)),
		series(ctr, "rid-b", "nux_container_memory_bytes", map[string]string{"type": "limit"}, pt(now, 1600)))

	rep, err := e.svc.Pressure(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Hosts) != 2 || rep.Hosts[0].ID != hostB || *rep.Hosts[0].CPUPercent < 94.9 || rep.Hosts[0].MemoryPercent != nil {
		t.Fatalf("hosts = %+v", rep.Hosts)
	}
	a := rep.Hosts[1]
	if *a.CPUPercent != 25 || *a.MemoryPercent != 90 || *a.DiskPercent != 50 || *a.Score != 90 {
		t.Fatalf("host a = %+v", a)
	}
	if a.Rank["memory"] != 1 || rep.Hosts[0].Rank["cpu"] != 1 || a.Rank["cpu"] != 2 {
		t.Fatalf("ranks: %v %v", a.Rank, rep.Hosts[0].Rank)
	}
	if len(rep.Containers) != 2 || rep.Containers[0].ID != ctrB || *rep.Containers[0].CPUPercent < 94.9 || *rep.Containers[0].MemoryPercent != 50 {
		t.Fatalf("containers = %+v", rep.Containers)
	}
	if *rep.Containers[1].MemoryPercent != 10 || *rep.Containers[1].CPUPercent != 50 { // 100 B of the host's 1000 B; no limit
		t.Fatalf("container a = %+v", rep.Containers[1])
	}
	one, _ := e.svc.Pressure(context.Background(), 1)
	if len(one.Hosts) != 1 || len(one.Containers) != 1 {
		t.Fatal("limit ignored")
	}
}

// TestRetention checks that each database drops blocks older than its retention (MET-5).
func TestRetention(t *testing.T) {
	clk := &clock{t: time.UnixMilli(1_900_000_000_000)}
	buf := &safeBuf{}
	svc, err := metrics.Open(metrics.Options{
		Dir: t.TempDir(), Log: slog.New(slog.NewTextHandler(buf, nil)), Inventory: testIndex(), Now: clk.now,
		FullRetention: 24 * time.Hour, DownsampledRetention: 48 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	lbl := labels.FromStrings(nameLabel, "nux_host_load_average", "target_type", "host", "target", hostA, "window", "1m")
	n, err := metrics.WriteForTest(svc, []labels.Labels{lbl}, clk.now().Add(-72*time.Hour), clk.now(), 10*time.Minute)
	if err != nil || n == 0 {
		t.Fatalf("seed: %d %v", n, err)
	}
	if err := svc.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldest := metrics.OldestForTest(svc)
	if age := clk.now().UnixMilli() - oldest; age > (24*time.Hour + 6*time.Hour).Milliseconds() {
		t.Fatalf("oldest full-resolution sample is %v old, retention is 24h", time.Duration(age)*time.Millisecond)
	}
}

// TestRetentionDownsampled checks the 5-minute database against DownsampledRetention (MET-5).
// The TSDB deletes whole 2-hour blocks, measured from the newest block rather than the wall
// clock, so the oldest sample may be up to one block plus the head's span older than the
// retention, but samples inside the retention must never be dropped.
func TestRetentionDownsampled(t *testing.T) {
	const downRetention = 48 * time.Hour
	clk := &clock{t: time.UnixMilli(1_900_000_000_000)}
	svc, err := metrics.Open(metrics.Options{
		Dir: t.TempDir(), Log: slog.New(slog.NewTextHandler(&safeBuf{}, nil)), Inventory: testIndex(), Now: clk.now,
		FullRetention: 24 * time.Hour, DownsampledRetention: downRetention,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	lbl := labels.FromStrings(nameLabel, "nux_host_load_average", "target_type", "host", "target", hostA, "window", "1m")
	seedFrom := clk.now().Add(-6 * 24 * time.Hour)
	if n, err := metrics.WriteDownForTest(svc, []labels.Labels{lbl}, seedFrom, clk.now(), 5*time.Minute); err != nil || n == 0 {
		t.Fatalf("seed: %d %v", n, err)
	}
	if oldest := metrics.OldestDownForTest(svc); oldest != seedFrom.UnixMilli() {
		t.Fatalf("seeded oldest = %d, want %d", oldest, seedFrom.UnixMilli())
	}

	if err := svc.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	age := time.Duration(clk.now().UnixMilli()-metrics.OldestDownForTest(svc)) * time.Millisecond
	if age > downRetention+6*time.Hour {
		t.Errorf("oldest 5-minute sample is %v old, retention is %v: old data was not dropped", age, downRetention)
	}
	if age < downRetention {
		t.Errorf("oldest 5-minute sample is %v old, but data inside the %v retention must be kept", age, downRetention)
	}
}

func TestPerformance24hOneHostFiftyContainers(t *testing.T) { // MET-6: under 1 second
	if testing.Short() {
		t.Skip("seeds 24h of data")
	}
	hosts := []inventory.Host{{ID: hostA, AgentID: "agent-a", Hostname: "alpha", CPUCount: 4, MemoryBytes: 1 << 30, Status: inventory.StatusOnline}}
	var ctrs []inventory.Container
	for i := 0; i < 50; i++ {
		ctrs = append(ctrs, inventory.Container{ID: fmt.Sprintf("01CTR%021d", i), HostID: hostA, RuntimeID: fmt.Sprintf("rid-%d", i), Name: fmt.Sprintf("c%d", i)})
	}
	clk := &clock{t: time.UnixMilli(1_900_000_000_000)}
	e := newEnvAt(t, t.TempDir(), clk, inventory.NewIndex(hosts, ctrs))
	now := clk.now()
	from := now.Add(-24 * time.Hour)
	var all []labels.Labels
	for _, c := range ctrs {
		all = append(all,
			labels.FromStrings(nameLabel, "nux_container_cpu_usage_ratio", "target_type", "container", "target", c.ID, "host", hostA),
			labels.FromStrings(nameLabel, "nux_container_memory_bytes", "target_type", "container", "target", c.ID, "host", hostA, "type", "working_set"))
	}
	all = append(all, labels.FromStrings(nameLabel, "nux_host_cpu_usage_ratio", "target_type", "host", "target", hostA, "cpu", "all"))
	if _, err := metrics.WriteForTest(e.svc, all, from, now, 15*time.Second); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	for _, c := range ctrs {
		r, err := e.svc.Query(context.Background(), metrics.Query{TargetType: metrics.TargetContainer, Target: c.ID, Metric: "nux_container_cpu_usage_ratio", From: from, To: now})
		if err != nil || len(r.Series) != 1 {
			t.Fatal(err, r)
		}
	}
	perQuery := time.Since(start) / time.Duration(len(ctrs))
	t.Logf("24h single-series query: %v average over %d containers", perQuery, len(ctrs))
	if perQuery > time.Second {
		t.Fatalf("24h query took %v", perQuery)
	}
	// Even all 51 targets one after another must fit in one second.
	if total := time.Since(start); total > time.Second {
		t.Fatalf("51 sequential 24h queries took %v", total)
	}
	start = time.Now()
	if _, err := e.svc.Pressure(context.Background(), 50); err != nil {
		t.Fatal(err)
	}
	t.Logf("pressure ranking: %v", time.Since(start))
	if time.Since(start) > time.Second {
		t.Fatal("pressure ranking too slow")
	}
}

func removeWatermark(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, "downsample.watermark")); err != nil {
		t.Fatal(err)
	}
}
