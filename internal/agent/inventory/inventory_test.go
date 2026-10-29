// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/agent/sockguard"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// ---- host facts ------------------------------------------------------------

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const mountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:5 / /proc rw - proc proc rw
24 22 8:2 / /boot rw - vfat /dev/sda2 rw
25 22 0:30 / /run rw - tmpfs tmpfs rw
26 22 8:3 /@ /data rw - btrfs /dev/sda3 rw,subvol=/@
27 22 8:3 /@home /data/home rw - btrfs /dev/sda3 rw,subvol=/@home
28 22 0:40 / /mnt/share rw - nfs4 server:/x rw
29 22 8:4 / /mnt/my\040disk rw - ext4 /dev/sda4 rw
30 22 8:5 / /unreadable rw - xfs /dev/sda5 rw
`

func fixtureSources(t *testing.T) hostSources {
	root := writeTree(t, map[string]string{
		"etc/os-release":            "NAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\n",
		"proc/sys/kernel/osrelease": "7.0.0-38-generic\n",
		"proc/meminfo":              "MemTotal:       16384000 kB\nMemFree:         1000 kB\n",
		"proc/cpuinfo":              "processor\t: 0\nmodel name\t: Test CPU @ 3GHz\n\nprocessor\t: 1\nmodel name\t: Test CPU @ 3GHz\n",
		"proc/stat":                 "cpu  1 2 3\nbtime 1790000000\n",
		"proc/self/mountinfo":       mountinfo,
	})
	return hostSources{
		root:     root,
		hostname: func() (string, error) { return "web-1", nil },
		interfaces: func() ([]ifaceAddr, error) {
			return []ifaceAddr{
				{"lo", net.ParseIP("127.0.0.1")},
				{"eth0", net.ParseIP("10.0.0.5")},
				{"eth0", net.ParseIP("fe80::1")},
				{"eth0", net.ParseIP("2001:db8::5")},
				{"docker0", net.ParseIP("172.17.0.1")},
				{"veth12", net.ParseIP("172.17.0.9")},
				{"wlan0", net.ParseIP("10.0.0.5")},
			}, nil
		},
		statfs: func(p string) (uint64, error) {
			if p == "/unreadable" {
				return 0, errors.New("permission denied")
			}
			return 100 << 30, nil
		},
	}
}

func TestINV1_HostFacts(t *testing.T) {
	h, err := fixtureSources(t).collectHost()
	if err != nil {
		t.Fatal(err)
	}
	if h.Hostname != "web-1" || h.Os != "linux" || h.Distro != "Ubuntu 26.04 LTS" || h.Kernel != "7.0.0-38-generic" || h.CpuCount != 2 || h.MemoryBytes != 16384000*1024 {
		t.Errorf("host = %+v", h)
	}
	if h.Facts["cpu_model"] != "Test CPU @ 3GHz" || h.Facts["boot_time_unix"] != "1790000000" {
		t.Errorf("facts = %v", h.Facts)
	}
	if h.Facts["ips"] != "10.0.0.5,2001:db8::5" {
		t.Errorf("ips = %q, want global host addresses only (no loopback, link-local or container networks)", h.Facts["ips"])
	}
	want := `[{"mount":"/","fstype":"ext4","total_bytes":107374182400},{"mount":"/boot","fstype":"vfat","total_bytes":107374182400},` +
		`{"mount":"/data","fstype":"btrfs","total_bytes":107374182400},{"mount":"/mnt/my disk","fstype":"ext4","total_bytes":107374182400}]`
	if h.Facts["disks"] != want {
		t.Errorf("disks = %s\nwant    %s", h.Facts["disks"], want)
	}
}

func TestINV1_MissingSourcesGivePartialFactsAndAnError(t *testing.T) {
	src := fixtureSources(t)
	src.root = t.TempDir() // nothing to read
	h, err := src.collectHost()
	if err == nil {
		t.Fatal("unreadable sources must be reported")
	}
	if h.Hostname != "web-1" || h.Os != "linux" || h.Arch == "" || h.Facts["ips"] == "" {
		t.Errorf("readable facts were lost: %+v", h)
	}
	if h.CpuCount == 0 {
		t.Error("the CPU count should fall back to the runtime's")
	}

	c := New(Config{Root: src.root, sources: src, SockguardSocket: "/nonexistent"})
	errs := c.Errors()
	if len(errs) != 1 || errs[0].Collector != "host" || errs[0].Code != string(errcode.AGTCol002) {
		t.Errorf("Errors() = %v", errs)
	}
}

func TestINV1_HostChangesAreAnnouncedOnce(t *testing.T) {
	src := fixtureSources(t)
	var mu sync.Mutex
	extra := false
	base := src.interfaces
	src.interfaces = func() ([]ifaceAddr, error) {
		mu.Lock()
		defer mu.Unlock()
		addrs, _ := base()
		if extra {
			addrs = append(addrs, ifaceAddr{"eth1", net.ParseIP("192.0.2.9")})
		}
		return addrs, nil
	}
	c := New(Config{sources: src, SockguardSocket: "/nonexistent", HostPoll: 15 * time.Millisecond, RetryInterval: time.Hour})
	snap, events, detach := c.Attach()
	defer detach()
	if snap.Host.Hostname != "web-1" {
		t.Fatalf("snapshot host = %+v", snap.Host)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case ev := <-events:
		t.Fatalf("an unchanged host announced %v", ev)
	case <-time.After(150 * time.Millisecond):
	}
	mu.Lock()
	extra = true
	mu.Unlock()
	select {
	case ev := <-events:
		if got := ev.GetHost().GetHost().Facts["ips"]; !strings.Contains(got, "192.0.2.9") {
			t.Errorf("event ips = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a new address was not announced")
	}
	select {
	case ev := <-events:
		t.Fatalf("the same change was announced twice: %v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

// ---- containers ------------------------------------------------------------

type fakeRuntime struct {
	mu         sync.Mutex
	version    string
	inspects   map[string]string
	order      []string
	requests   []string
	eventLines chan string
	dropEvents chan struct{} // closing a send on it ends the current event stream
	sock       string
}

func inspectJSON(id, name, state string, restarts int, ports string) string {
	return fmt.Sprintf(`{"Id":%q,"Name":"/%s","Created":"2026-10-25T10:00:00.123456789Z","RestartCount":%d,"State":{"Status":%q},
 "Config":{"Image":"nginx:1.27","Labels":{"app":"%s","password":"[redacted]"}},"NetworkSettings":{"Ports":%s}}`, id, name, restarts, state, name, ports)
}

const dockerVersion = `{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine"}]}`

func startRuntime(t *testing.T, sock string) *fakeRuntime {
	t.Helper()
	rt := &fakeRuntime{version: dockerVersion, inspects: map[string]string{}, eventLines: make(chan string, 64), dropEvents: make(chan struct{}, 4), sock: sock}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, rt.version) })
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		parts := make([]string, 0, len(rt.order))
		for _, id := range rt.order {
			if _, ok := rt.inspects[id]; ok {
				parts = append(parts, fmt.Sprintf(`{"Id":%q}`, id))
			}
		}
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(parts, ","))
	})
	mux.HandleFunc("/containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		body, ok := rt.inspects[r.PathValue("id")]
		rt.mu.Unlock()
		if !ok {
			http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, body)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case line := <-rt.eventLines:
				_, _ = fmt.Fprintln(w, line)
				w.(http.Flusher).Flush()
			case <-rt.dropEvents:
				return
			case <-r.Context().Done():
				return
			}
		}
	})
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		rt.requests = append(rt.requests, r.Method+" "+r.RequestURI)
		rt.mu.Unlock()
		mux.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return rt
}

func (rt *fakeRuntime) set(id, body string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if _, ok := rt.inspects[id]; !ok {
		rt.order = append(rt.order, id)
	}
	rt.inspects[id] = body
}

func (rt *fakeRuntime) inspectCount(id string) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	n := 0
	for _, r := range rt.requests {
		if strings.HasPrefix(r, "GET /containers/"+id+"/json") {
			n++
		}
	}
	return n
}

func (rt *fakeRuntime) remove(id string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.inspects, id)
}

func evLine(action, id string) string {
	return fmt.Sprintf(`{"Type":"container","Action":%q,"Actor":{"ID":%q,"Attributes":{"name":"x"}},"time":1790000000}`, action, id)
}

func sockPath(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "inv") // short: unix socket paths are limited to ~108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, "s.sock")
}

func startCollector(t *testing.T, sock string, tweak func(*Config)) *Collector {
	t.Helper()
	cfg := Config{SockguardSocket: sock, sources: fixtureSources(t), RetryInterval: 30 * time.Millisecond, ReconnectDelay: 10 * time.Millisecond, HostPoll: time.Hour}
	if tweak != nil {
		tweak(&cfg)
	}
	c := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func snapshotOf(c *Collector) *agentv1.InventorySnapshot {
	snap, _, detach := c.Attach()
	detach()
	return snap
}

func containerByName(s *agentv1.InventorySnapshot, name string) *agentv1.Container {
	for _, ct := range s.Containers {
		if ct.Name == name {
			return ct
		}
	}
	return nil
}

func TestINV1_ContainersAppearInTheSnapshot(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	rt.set("aaa111", inspectJSON("aaa111", "web", "running", 3, `{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}],"443/tcp":[{"HostIp":"0.0.0.0","HostPort":"8443"}],"9000/udp":null}`))
	rt.set("bbb222", inspectJSON("bbb222", "job", "exited", 0, `{}`))
	c := startCollector(t, sock, nil)

	waitFor(t, "two containers", func() bool { return len(snapshotOf(c).Containers) == 2 })
	snap := snapshotOf(c)
	web := containerByName(snap, "web")
	if web.Runtime != agentv1.Runtime_RUNTIME_DOCKER || web.RuntimeId != "aaa111" || web.Image != "nginx:1.27" || web.State != "running" || web.RestartCount != 3 {
		t.Errorf("web = %v", web)
	}
	if web.CreatedAtUnixMs != time.Date(2026, 10, 25, 10, 0, 0, 123000000, time.UTC).UnixMilli() {
		t.Errorf("created = %d", web.CreatedAtUnixMs)
	}
	var ports []string
	for _, p := range web.Ports {
		ports = append(ports, fmt.Sprintf("%s:%d->%d/%s", p.HostIp, p.HostPort, p.ContainerPort, p.Protocol))
	}
	if fmt.Sprint(ports) != "[0.0.0.0:8080->80/tcp :::8080->80/tcp 0.0.0.0:8443->443/tcp]" {
		t.Errorf("ports (published only, in a stable order) = %v", ports)
	}
	if web.Labels["app"] != "web" || web.Labels["password"] != "[redacted]" {
		t.Errorf("labels = %v", web.Labels)
	}
	if job := containerByName(snap, "job"); job.State != "exited" || len(job.Ports) != 0 {
		t.Errorf("job = %v", job)
	}
	if snap.Host.Hostname != "web-1" {
		t.Error("the snapshot lacks the host facts")
	}
	if len(c.Errors()) != 0 {
		t.Errorf("Errors() = %v", c.Errors())
	}
}

func TestINV1_PodmanIsRecognised(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	rt.version = `{"Platform":{"Name":"Podman Engine"},"Components":[{"Name":"Podman Engine"}]}`
	rt.set("ccc333", inspectJSON("ccc333", "pod-web", "running", 0, `{}`))
	c := startCollector(t, sock, nil)
	waitFor(t, "a container", func() bool { return len(snapshotOf(c).Containers) == 1 })
	if got := snapshotOf(c).Containers[0].Runtime; got != agentv1.Runtime_RUNTIME_PODMAN {
		t.Errorf("runtime = %v", got)
	}
}

func recvEvent(t *testing.T, ch <-chan *agentv1.InventoryEvent) *agentv1.ContainerChange {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("event channel closed")
		}
		if ev.GetContainer() == nil {
			t.Fatalf("not a container change: %v", ev)
		}
		return ev.GetContainer()
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
		return nil
	}
}

func TestINV2_ContainerChangesAreAnnouncedAsTheyHappen(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	c := startCollector(t, sock, nil)
	waitFor(t, "first sync", func() bool { return len(c.Errors()) == 0 && c.runtimeKnown() })

	_, events, detach := c.Attach()
	defer detach()
	started := time.Now()

	rt.set("ddd444", inspectJSON("ddd444", "api", "created", 0, `{}`))
	rt.eventLines <- evLine("create", "ddd444")
	if ch := recvEvent(t, events); ch.Kind != agentv1.ContainerChange_KIND_CREATED || ch.Container.Name != "api" || ch.Container.State != "created" {
		t.Errorf("create -> %v", ch)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("a change took %v to announce; INV-2 allows 10 s end to end", took)
	}

	rt.set("ddd444", inspectJSON("ddd444", "api", "running", 0, `{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"80"}]}`))
	rt.eventLines <- evLine("start", "ddd444")
	if ch := recvEvent(t, events); ch.Kind != agentv1.ContainerChange_KIND_STARTED || ch.Container.State != "running" || len(ch.Container.Ports) != 1 {
		t.Errorf("start -> %v", ch)
	}

	rt.eventLines <- evLine("exec_create: sh", "ddd444") // nothing the inventory reports
	rt.eventLines <- evLine("attach", "ddd444")
	rt.eventLines <- evLine("kill", "ddd444")
	rt.eventLines <- `not json at all`
	rt.eventLines <- `{"Type":"network","Action":"connect","Actor":{"ID":"net1"}}`

	rt.set("ddd444", inspectJSON("ddd444", "api", "exited", 1, `{}`))
	before := rt.inspectCount("ddd444")
	rt.eventLines <- evLine("die", "ddd444")
	rt.eventLines <- evLine("stop", "ddd444") // same state again: must not announce twice
	if ch := recvEvent(t, events); ch.Kind != agentv1.ContainerChange_KIND_STOPPED || ch.Container.State != "exited" || ch.Container.RestartCount != 1 {
		t.Errorf("die -> %v", ch)
	}
	waitFor(t, "both events to be handled", func() bool { return rt.inspectCount("ddd444") >= before+2 })

	rt.set("ddd444", inspectJSON("ddd444", "api-renamed", "exited", 1, `{}`))
	rt.eventLines <- evLine("rename", "ddd444")
	if ch := recvEvent(t, events); ch.Kind != agentv1.ContainerChange_KIND_UPDATED || ch.Container.Name != "api-renamed" {
		t.Errorf("rename -> %v", ch)
	}

	rt.remove("ddd444")
	rt.eventLines <- evLine("destroy", "ddd444")
	if ch := recvEvent(t, events); ch.Kind != agentv1.ContainerChange_KIND_REMOVED || ch.Container.RuntimeId != "ddd444" {
		t.Errorf("destroy -> %v", ch)
	}
	select {
	case ev := <-events:
		t.Errorf("an unexpected extra event: %v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	if len(snapshotOf(c).Containers) != 0 {
		t.Error("the removed container is still in the snapshot")
	}
}

func (c *Collector) runtimeKnown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtime != agentv1.Runtime_RUNTIME_UNSPECIFIED
}

func TestEventForAContainerThatVanishedMeansRemoved(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	rt.set("eee555", inspectJSON("eee555", "tmp", "running", 0, `{}`))
	c := startCollector(t, sock, nil)
	waitFor(t, "sync", func() bool { return len(snapshotOf(c).Containers) == 1 })
	_, events, detach := c.Attach()
	defer detach()

	rt.remove("eee555") // gone before the collector looks, and no destroy event is seen
	rt.eventLines <- evLine("die", "eee555")
	if ch := recvEvent(t, events); ch.Kind != agentv1.ContainerChange_KIND_REMOVED || ch.Container.RuntimeId != "eee555" {
		t.Errorf("got %v", ch)
	}
}

func TestEventsAreResyncedAfterTheStreamBreaks(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	rt.set("f1", inspectJSON("f1", "keep", "running", 0, `{}`))
	rt.set("f2", inspectJSON("f2", "change", "running", 0, `{}`))
	rt.set("f3", inspectJSON("f3", "gone", "running", 0, `{}`))
	c := startCollector(t, sock, nil)
	waitFor(t, "sync", func() bool { return len(snapshotOf(c).Containers) == 3 })
	_, events, detach := c.Attach()
	defer detach()

	// Events are lost while the stream is down: the next resync must catch up.
	rt.dropEvents <- struct{}{}
	rt.set("f2", inspectJSON("f2", "change", "exited", 0, `{}`))
	rt.remove("f3")
	rt.set("f4", inspectJSON("f4", "new", "running", 0, `{}`))

	got := map[string]agentv1.ContainerChange_Kind{}
	for range 3 {
		ch := recvEvent(t, events)
		got[ch.Container.RuntimeId] = ch.Kind
	}
	want := map[string]agentv1.ContainerChange_Kind{"f2": agentv1.ContainerChange_KIND_UPDATED, "f3": agentv1.ContainerChange_KIND_REMOVED, "f4": agentv1.ContainerChange_KIND_CREATED}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("resync announced %v, want %v", got, want)
	}
}

func TestAnAbsentRuntimeIsReportedAndFoundLater(t *testing.T) {
	sock := sockPath(t)
	c := startCollector(t, sock, nil)

	waitFor(t, "a collector error", func() bool { return len(c.Errors()) == 1 })
	if e := c.Errors()[0]; e.Collector != "containers" || e.Code != string(errcode.AGTCol001) || e.AtUnixMs == 0 {
		t.Errorf("error = %v", e)
	}
	if snapshotOf(c).Host.Hostname != "web-1" {
		t.Error("host facts must still be reported without a runtime")
	}

	rt := startRuntime(t, sock)
	rt.set("g1", inspectJSON("g1", "late", "running", 0, `{}`))
	waitFor(t, "the late runtime", func() bool { return len(snapshotOf(c).Containers) == 1 && len(c.Errors()) == 0 })
}

func TestCollectorOnlyAsksForWhatSockguardAllows(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	rt.set("h1", inspectJSON("h1", "a", "running", 0, `{}`))
	c := startCollector(t, sock, nil)
	waitFor(t, "sync", func() bool { return len(snapshotOf(c).Containers) == 1 })
	rt.eventLines <- evLine("start", "h1")
	rt.set("h1", inspectJSON("h1", "a", "exited", 0, `{}`))
	rt.eventLines <- evLine("die", "h1")
	waitFor(t, "update", func() bool { return containerByName(snapshotOf(c), "a").State == "exited" })

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.requests) < 4 {
		t.Fatalf("only %d requests recorded: %v", len(rt.requests), rt.requests)
	}
	for _, r := range rt.requests {
		method, uri, _ := strings.Cut(r, " ")
		if _, err := sockguard.Decide(method, uri); err != nil {
			t.Errorf("the collector sent %q, which nux-sockguard would refuse", r)
		}
	}
}

func TestSlowSubscribersAreClosedNotBuffered(t *testing.T) {
	c := New(Config{sources: fixtureSources(t), SockguardSocket: "/nonexistent"})
	_, slow, detachSlow := c.Attach()
	_, fast, detachFast := c.Attach()
	defer detachFast()
	defer detachSlow()

	for i := range subscriberBuf + 5 {
		c.mu.Lock()
		c.emitContainerLocked(agentv1.ContainerChange_KIND_UPDATED, &agentv1.Container{RuntimeId: fmt.Sprint(i)})
		c.mu.Unlock()
		select { // the fast subscriber keeps up
		case <-fast:
		default:
			t.Fatal("fast subscriber missed an event")
		}
	}
	n := 0
	for range slow {
		n++
	}
	if n != subscriberBuf {
		t.Errorf("the slow subscriber got %d events before being closed, want %d", n, subscriberBuf)
	}
	snap, again, detach := c.Attach() // attaching again yields a fresh, consistent start
	defer detach()
	if snap.Host == nil || again == nil {
		t.Error("re-attach failed")
	}
}

func TestContainerCountAndLabelsAreBounded(t *testing.T) {
	sock := sockPath(t)
	rt := startRuntime(t, sock)
	for i := range maxContainers + 25 {
		id := fmt.Sprintf("c%05d", i)
		rt.set(id, inspectJSON(id, id, "running", 0, `{}`))
	}
	c := startCollector(t, sock, nil)
	waitFor(t, "capped sync", func() bool { return len(snapshotOf(c).Containers) == maxContainers })
	time.Sleep(100 * time.Millisecond)
	if n := len(snapshotOf(c).Containers); n != maxContainers {
		t.Errorf("tracking %d containers, want exactly %d", n, maxContainers)
	}

	big := map[string]string{}
	for i := range 200 {
		big[fmt.Sprintf("label%03d", i)] = strings.Repeat("v", 5000)
	}
	got := boundedLabels(big)
	if len(got) != maxLabels {
		t.Errorf("%d labels kept, want %d", len(got), maxLabels)
	}
	for _, v := range got {
		if len(v) > maxLabelValue {
			t.Fatalf("a label value of %d bytes was kept", len(v))
		}
	}
}

func TestUnexpectedStatusesAreErrors(t *testing.T) {
	sock := sockPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // what sockguard answers to a refused call
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	c := startCollector(t, sock, nil)
	waitFor(t, "an error", func() bool { return len(c.Errors()) == 1 })
	if len(snapshotOf(c).Containers) != 0 {
		t.Error("containers appeared from a refused call")
	}
}
