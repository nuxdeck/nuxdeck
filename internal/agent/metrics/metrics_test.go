// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const cid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

var running = func() []*agentv1.Container {
	return []*agentv1.Container{{RuntimeId: cid, State: "running", RestartCount: 3}, {RuntimeId: "stopped", State: "exited"}}
}

func fakeStatfs(path string) (uint64, uint64, uint64, error) {
	if strings.HasSuffix(path, "/mnt/my data") {
		return 1000, 400, 300, nil
	}
	return 2000, 500, 400, nil
}

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/root")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func find(t *testing.T, rs []reading, metric string, kv ...string) float64 {
	t.Helper()
	want := lbl(kv...)
next:
	for _, r := range rs {
		if r.metric != metric || len(r.labels) != len(want) {
			continue
		}
		for k, v := range want {
			if r.labels[k] != v {
				continue next
			}
		}
		return r.value
	}
	t.Fatalf("no reading %s%v", metric, want)
	return 0
}

func TestHostCollector(t *testing.T) { // MET-1
	h := newHostCollector("testdata/root", fakeStatfs)
	rs, err := h.collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		metric string
		kv     []string
		want   float64
	}{
		{"nux_host_cpu_seconds_total", []string{"cpu", "all", "mode", "user"}, 10},
		{"nux_host_cpu_seconds_total", []string{"cpu", "all", "mode", "iowait"}, 3},
		{"nux_host_cpu_seconds_total", []string{"cpu", "1", "mode", "steal"}, 0.05},
		{"nux_host_load_average", []string{"window", "5m"}, 0.48},
		{"nux_host_memory_bytes", []string{"type", "total"}, 16000000 * 1024},
		{"nux_host_memory_bytes", []string{"type", "used"}, 8000000 * 1024},
		{"nux_host_swap_bytes", []string{"type", "used"}, 500000 * 1024},
		{"nux_host_filesystem_bytes", []string{"mount", "/mnt/my data", "device", "/dev/sdb1", "fstype", "xfs", "type", "used"}, 600},
		{"nux_host_filesystem_bytes", []string{"mount", "/", "device", "/dev/sda1", "fstype", "ext4", "type", "avail"}, 400},
		{"nux_host_disk_io_bytes_total", []string{"device", "sda", "direction", "read"}, 20000 * 512},
		{"nux_host_disk_io_ops_total", []string{"device", "sda1", "direction", "write"}, 400},
		{"nux_host_disk_io_seconds_total", []string{"device", "sda"}, 0.4},
		{"nux_host_network_bytes_total", []string{"interface", "eth0", "direction", "tx"}, 500000},
		{"nux_host_network_errors_total", []string{"interface", "eth0", "direction", "rx"}, 3},
		{"nux_host_network_drops_total", []string{"interface", "eth0", "direction", "tx"}, 2},
	} {
		if got := find(t, rs, tc.metric, tc.kv...); got != tc.want {
			t.Errorf("%s%v = %v, want %v", tc.metric, tc.kv, got, tc.want)
		}
	}
	for _, r := range rs {
		if r.labels["device"] == "loop0" || r.labels["interface"] == "lo" || r.labels["device"] == "sdb" || r.labels["mount"] == "/proc" || r.labels["mount"] == "/bind" {
			t.Errorf("unexpected series %v", r)
		}
	}
}

func TestParsersRejectGarbage(t *testing.T) {
	for name, fn := range map[string]func() error{
		"stat":    func() error { _, _, _, err := parseStat([]byte("garbage\n")); return err },
		"stat-nv": func() error { _, _, _, err := parseStat([]byte("cpu a b c d e f g h\n")); return err },
		"load":    func() error { _, err := parseLoad([]byte("1")); return err },
		"meminfo": func() error { _, err := parseMeminfo([]byte("Foo: 1 kB\n")); return err },
	} {
		if fn() == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if got := parseDiskstats([]byte("1 2 sda x y z\n8 0 sda a b c d e f g h i j k\n")); len(got) != 0 {
		t.Errorf("garbage diskstats gave %d readings", len(got))
	}
	if got := parseNetDev([]byte("eth0: 1 2\nbad line\n"), 10); len(got) != 0 {
		t.Errorf("garbage net/dev gave %d interfaces", len(got))
	}
}

func TestHostCPURatio(t *testing.T) {
	root := fixture(t)
	h := newHostCollector(root, fakeStatfs)
	if _, err := h.collect(); err != nil {
		t.Fatal(err)
	}
	// +100 busy ticks, +100 idle ticks since the first sample: 50 % busy.
	write(t, filepath.Join(root, "proc/stat"), "cpu  1100 50 500 8100 300 20 30 10 0 0\ncpu0 1 0 0 0 0 0 0 0\n")
	rs, err := h.collect()
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, rs, "nux_host_cpu_usage_ratio", "cpu", "all"); got < 0.49 || got > 0.51 {
		t.Errorf("ratio = %v, want 0.5", got)
	}
}

func TestContainerCgroups(t *testing.T) { // MET-2
	c := newContainerCollector("testdata/root", "", running)
	now := time.Unix(1000, 0)
	rs, err := c.collect(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		metric string
		kv     []string
		want   float64
	}{
		{"nux_container_cpu_seconds_total", []string{"mode", "user"}, 2},
		{"nux_container_cpu_seconds_total", []string{"mode", "system"}, 1},
		{"nux_container_cpu_throttled_seconds_total", nil, 0.5},
		{"nux_container_memory_bytes", []string{"type", "usage"}, 104857600},
		{"nux_container_memory_bytes", []string{"type", "limit"}, 536870912},
		{"nux_container_memory_bytes", []string{"type", "working_set"}, 104857600 - 4194304},
		{"nux_container_memory_oom_kills_total", nil, 2},
		{"nux_container_blkio_bytes_total", []string{"direction", "read"}, 1500},
		{"nux_container_blkio_bytes_total", []string{"direction", "write"}, 2000},
		{"nux_container_blkio_ops_total", []string{"direction", "write"}, 20},
		{"nux_container_network_bytes_total", []string{"direction", "rx"}, 3000},
		{"nux_container_network_errors_total", []string{"direction", "rx"}, 1},
		{"nux_container_restart_count", nil, 3},
	} {
		if got := find(t, rs, tc.metric, tc.kv...); got != tc.want {
			t.Errorf("%s%v = %v, want %v", tc.metric, tc.kv, got, tc.want)
		}
	}
	for _, r := range rs {
		if r.id != cid {
			t.Errorf("series for %q, only the running container should report", r.id)
		}
	}
}

func TestContainerUnlimitedMemoryAndRatio(t *testing.T) {
	root := fixture(t)
	dir := filepath.Join(root, "sys/fs/cgroup/system.slice/docker-"+cid+".scope")
	write(t, filepath.Join(dir, "memory.max"), "max\n")
	c := newContainerCollector(root, "", running)
	if _, err := c.collect(context.Background(), time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "cpu.stat"), "usage_usec 5000000\nuser_usec 3000000\nsystem_usec 2000000\n")
	rs, err := c.collect(context.Background(), time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, rs, "nux_container_cpu_usage_ratio"); got != 0.2 {
		t.Errorf("ratio = %v, want 0.2", got)
	}
	for _, r := range rs {
		if r.metric == "nux_container_memory_bytes" && r.labels["type"] == "limit" {
			t.Error("an unlimited container must not report a limit")
		}
	}
}

func TestContainerFoundBySearch(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sys/fs/cgroup/custom.slice/crio-"+cid+".scope")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "cpu.stat"), "usage_usec 1\nuser_usec 1\nsystem_usec 0\n")
	write(t, filepath.Join(dir, "memory.current"), "10\n")
	rs, err := newContainerCollector(root, "", running).collect(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, rs, "nux_container_memory_bytes", "type", "usage"); got != 10 {
		t.Errorf("usage = %v", got)
	}
}

func TestContainerStatsFallback(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotPath, gotMethod string
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"cpu_stats":{"cpu_usage":{"total_usage":2000000000,"usage_in_kernelmode":500000000,"usage_in_usermode":1500000000}},
"memory_stats":{"usage":2048,"limit":4096,"stats":{"inactive_file":1024}},
"networks":{"eth0":{"rx_bytes":7,"tx_bytes":9,"rx_packets":1,"tx_packets":2,"rx_errors":0,"tx_errors":1}},
"blkio_stats":{"io_service_bytes_recursive":[{"op":"Read","value":11},{"op":"Write","value":22}]}}`))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := newContainerCollector(t.TempDir(), sock, running) // no cgroup tree: forces the fallback
	rs, err := c.collect(context.Background(), time.Unix(5, 0))
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotPath != "/containers/"+cid+"/stats" {
		t.Errorf("request %s %s", gotMethod, gotPath)
	}
	for metric, want := range map[string]float64{"nux_container_cpu_seconds_total": 1.5} {
		if got := find(t, rs, metric, "mode", "user"); got != want {
			t.Errorf("%s = %v", metric, got)
		}
	}
	if got := find(t, rs, "nux_container_memory_bytes", "type", "working_set"); got != 1024 {
		t.Errorf("working set = %v", got)
	}
	if got := find(t, rs, "nux_container_network_bytes_total", "direction", "tx"); got != 9 {
		t.Errorf("tx = %v", got)
	}
	if got := find(t, rs, "nux_container_blkio_bytes_total", "direction", "write"); got != 22 {
		t.Errorf("write = %v", got)
	}
}

func TestContainerFailureIsReported(t *testing.T) {
	_, err := newContainerCollector(t.TempDir(), "", running).collect(context.Background(), time.Now())
	if err == nil {
		t.Fatal("want an error when neither cgroups nor the API work")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestService(t *testing.T, root string, now *time.Time) *Service {
	t.Helper()
	return New(Config{Root: root, Containers: running, statfs: fakeStatfs, Now: func() time.Time { return *now }})
}

func drain(s *Service, replayBefore time.Time) (batches []*agentv1.MetricBatch) {
	for {
		b, commit := s.Next(replayBefore)
		if b == nil {
			return batches
		}
		commit()
		batches = append(batches, b)
	}
}

func pointsOf(bs []*agentv1.MetricBatch, metric string, kv ...string) (vals []float64) {
	want := lbl(kv...)
	for _, b := range bs {
		for _, s := range b.Series {
			ok := s.Metric == metric && len(s.Labels) == len(want)
			for k, v := range want {
				ok = ok && s.Labels[k] == v
			}
			if ok {
				for _, p := range s.Points {
					vals = append(vals, p.Value)
				}
			}
		}
	}
	return vals
}

func TestCounterResetValues(t *testing.T) {
	root := fixture(t)
	now := time.Unix(1000, 0)
	s := newTestService(t, root, &now)
	s.Tick(context.Background()) // user = 10 s
	for _, c := range []string{"cpu  2000 0 0 0 0 0 0 0\n", "cpu  30 0 0 0 0 0 0 0\n", "cpu  80 0 0 0 0 0 0 0\n"} {
		now = now.Add(15 * time.Second)
		write(t, filepath.Join(root, "proc/stat"), c)
		s.Tick(context.Background())
	}
	got := pointsOf(drain(s, time.Time{}), "nux_host_cpu_seconds_total", "cpu", "all", "mode", "user")
	want := []float64{10, 20, 20.3, 20.8}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if d := got[i] - want[i]; d > 1e-9 || d < -1e-9 {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestCollectorsAreIndependent(t *testing.T) {
	root := fixture(t)
	if err := os.Remove(filepath.Join(root, "proc/diskstats")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "sys")); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	s := newTestService(t, root, &now)
	s.Tick(context.Background())
	codes := map[string]string{}
	for _, e := range s.Errors() {
		codes[e.Collector] = e.Code
	}
	if codes[collectorHost] != string(errcode.AGTCol003) || codes[collectorContainers] != string(errcode.AGTCol004) {
		t.Errorf("errors = %v", codes)
	}
	bs := drain(s, time.Time{})
	if len(pointsOf(bs, "nux_host_memory_bytes", "type", "total")) != 1 || len(pointsOf(bs, "nux_host_network_bytes_total", "interface", "eth0", "direction", "rx")) != 1 {
		t.Error("remaining host metrics must still be reported")
	}
	if len(pointsOf(bs, "nux_host_disk_io_ops_total", "device", "sda", "direction", "read")) != 0 {
		t.Error("the failed part must not report")
	}
	// Recovery clears the error.
	if err := os.CopyFS(root+"/restore", os.DirFS("testdata/root")); err != nil {
		t.Fatal(err)
	}
	s2 := newTestService(t, root+"/restore", &now)
	s2.Tick(context.Background())
	if len(s2.Errors()) != 0 {
		t.Errorf("errors = %v", s2.Errors())
	}
}

func TestIntervalClamp(t *testing.T) { // MET-4
	for in, want := range map[uint32]time.Duration{
		0: 15 * time.Second, 1: 5 * time.Second, 5: 5 * time.Second, 15: 15 * time.Second, 60: 60 * time.Second, 61: 60 * time.Second, 4000000000: 60 * time.Second,
	} {
		if got := ClampInterval(in); got != want {
			t.Errorf("ClampInterval(%d) = %v, want %v", in, got, want)
		}
	}
	now := time.Now()
	s := newTestService(t, "testdata/root", &now)
	if s.Interval() != DefaultInterval {
		t.Fatalf("default = %v", s.Interval())
	}
	s.SetInterval(2)
	if s.Interval() != MinInterval {
		t.Fatalf("after update = %v", s.Interval())
	}
	s.SetInterval(30)
	s.SetInterval(45) // a second update before Run reads the first must replace it
	if d := <-s.interval; d != 45*time.Second {
		t.Fatalf("pending interval = %v", d)
	}
}

func TestRunAppliesIntervalLive(t *testing.T) {
	root := fixture(t)
	now := time.Unix(1000, 0)
	s := newTestService(t, root, &now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	select {
	case <-s.Notify():
	case <-time.After(5 * time.Second):
		t.Fatal("no first sample")
	}
	s.SetInterval(7)
	deadline := time.After(2 * time.Second)
	for s.Interval() != 7*time.Second {
		select {
		case <-deadline:
			t.Fatal("interval not applied")
		case <-time.After(time.Millisecond):
		}
	}
}

func mkSamples(n int, series int, ts int64) []sample {
	ids := make([]*seriesID, series)
	for i := range ids {
		ids[i] = newSeriesID(agentv1.TargetKind_TARGET_KIND_CONTAINER, fmt.Sprintf("container-%064d", i), "nux_container_network_bytes_total", lbl("direction", "rx", "interface", fmt.Sprint(i)))
	}
	out := make([]sample, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, sample{s: ids[i%series], ts: ts + int64(i/series), v: float64(i)})
	}
	return out
}

func TestBufferOverflowDropsOldest(t *testing.T) { // AGT-5
	now := time.UnixMilli(10_000)
	b := NewBuffer(time.Hour, 100, func() time.Time { return now })
	b.push(mkSamples(80, 1, 1000))
	b.push(mkSamples(50, 1, 2000))
	if b.Len() != 100 || b.Dropped() != 30 {
		t.Fatalf("len %d dropped %d", b.Len(), b.Dropped())
	}
	batch, commit := b.next(0)
	if first := batch.Series[0].Points[0].TsUnixMs; first != 1030 {
		t.Errorf("oldest kept = %d, want 1030", first)
	}
	commit()
	if b.Len() != 0 {
		t.Errorf("len after commit = %d", b.Len())
	}
}

func TestBufferRetention(t *testing.T) { // AGT-5
	now := time.UnixMilli(0).Add(time.Hour)
	b := NewBuffer(15*time.Minute, 1000, func() time.Time { return now })
	old := now.Add(-16 * time.Minute).UnixMilli()
	fresh := now.Add(-14 * time.Minute).UnixMilli()
	b.push(append(mkSamples(3, 1, old), mkSamples(3, 1, fresh)...))
	if b.Len() != 3 {
		t.Fatalf("len = %d, want only the samples from the last 15 minutes", b.Len())
	}
}

func TestBufferReplayFlagAndCommit(t *testing.T) {
	now := time.UnixMilli(10_000)
	b := NewBuffer(time.Hour, 1000, func() time.Time { return now })
	b.push(mkSamples(4, 2, 1000)) // offline
	b.push(mkSamples(4, 2, 5000)) // live
	replayed, commit := b.next(5000)
	if !replayed.Replayed || points(replayed) != 4 {
		t.Fatalf("first batch: replayed=%v points=%d", replayed.Replayed, points(replayed))
	}
	b.push(mkSamples(2, 2, 6000))
	commit() // must remove exactly the replayed batch, not the newer samples
	live, commit := b.next(5000)
	if live.Replayed || points(live) != 6 {
		t.Fatalf("second batch: replayed=%v points=%d", live.Replayed, points(live))
	}
	// Without commit the batch stays: a failed send loses nothing.
	again, _ := b.next(5000)
	if points(again) != 6 {
		t.Fatalf("uncommitted batch vanished: %d", points(again))
	}
	commit()
	if nb, _ := b.next(5000); nb != nil {
		t.Fatal("buffer should be empty")
	}
}

func points(b *agentv1.MetricBatch) (n int) {
	for _, s := range b.Series {
		n += len(s.Points)
	}
	return n
}

func TestBatchesStayUnderOneMB(t *testing.T) {
	now := time.UnixMilli(100_000)
	b := NewBuffer(time.Hour, 2_000_000, func() time.Time { return now })
	// 1500 containers x 20 series x 4 ticks, the worst case for one connection's backlog.
	b.push(mkSamples(1500*20*4, 1500*20, 1000))
	total, batches := 0, 0
	for {
		batch, commit := b.next(5000)
		if batch == nil {
			break
		}
		if size := proto.Size(batch); size >= 1<<20 {
			t.Fatalf("batch of %d bytes", size)
		}
		total += points(batch)
		batches++
		commit()
	}
	if total != 1500*20*4 || batches < 2 {
		t.Fatalf("points %d in %d batches", total, batches)
	}
}

// The agent is read-only (ADR-010): collectors must never modify anything they read.
func TestCollectorsDoNotWrite(t *testing.T) {
	root := fixture(t)
	before := hashTree(t, root)
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			mode := os.FileMode(0o444)
			if d.IsDir() {
				mode = 0o555
			}
			_ = os.Chmod(p, mode) //nolint:gosec // test fixture
		}
		return nil
	})
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(p string, _ fs.DirEntry, _ error) error {
			_ = os.Chmod(p, 0o755) //nolint:gosec // test fixture
			return nil
		})
	})
	now := time.Unix(1000, 0)
	s := newTestService(t, root, &now)
	s.Tick(context.Background())
	s.Tick(context.Background())
	if len(s.Errors()) != 0 {
		t.Fatalf("collectors failed on a read-only tree: %v", s.Errors())
	}
	if after := hashTree(t, root); after != before {
		t.Fatal("a collector changed the tree")
	}
}

func TestSourceHasNoWriteCalls(t *testing.T) {
	forbidden := regexp.MustCompile(`os\.(Create|WriteFile|OpenFile|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Chmod|Chown|Truncate|Symlink|Link)\b|syscall\.(Write|Unlink|Mkdir|Rename|Mount)|http\.(MethodPost|MethodPut|MethodDelete|MethodPatch)|\.Post\(`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // package source
		if err != nil {
			t.Fatal(err)
		}
		if m := forbidden.Find(b); m != nil {
			t.Errorf("%s uses %q", f, m)
		}
	}
}

func hashTree(t *testing.T, root string) [32]byte {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(h, p)
		if !d.IsDir() {
			b, err := os.ReadFile(p) //nolint:gosec // test fixture
			if err != nil {
				return err
			}
			_, _ = h.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
