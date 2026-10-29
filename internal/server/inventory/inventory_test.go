// SPDX-License-Identifier: AGPL-3.0-only

package inventory_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

type env struct {
	t     *testing.T
	db    *store.Store
	pki   *pki.Service
	svc   *inventory.Service
	clock atomic.Int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateAdmin(context.Background(), auth.User{ID: "01ADMIN", Email: "ada@example.com", Name: "Ada", PasswordHash: "x", CreatedAt: time.Now()},
		audit.Event{ActorType: "user", ActorID: "01ADMIN", Action: "setup.complete", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, pki: pki.NewService(db, ca)}
	e.clock.Store(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).UnixMilli())
	e.svc = e.newService()
	return e
}

func (e *env) now() time.Time { return time.UnixMilli(e.clock.Load()).UTC() }

func (e *env) newService() *inventory.Service {
	svc, err := inventory.NewService(e.db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		e.t.Fatal(err)
	}
	svc.Now = e.now
	return svc
}

func (e *env) advance(d time.Duration) { e.clock.Add(d.Milliseconds()) }

// agent enrols a real agent, so hosts have an agent to belong to.
func (e *env) agent() string {
	e.t.Helper()
	tok, err := e.pki.CreateToken(context.Background(), pki.Actor{UserID: "01ADMIN"}, pki.TokenRequest{ServerURL: "https://nux.example.com:8444"})
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	res, err := e.pki.Enroll(context.Background(), pki.EnrollRequest{Token: tok.Token, CSRDER: csr, Hostname: "h", OS: "linux", Arch: "amd64"})
	if err != nil {
		e.t.Fatal(err)
	}
	return res.AgentID
}

func hostFacts(name string) *agentv1.HostFacts {
	return &agentv1.HostFacts{
		Hostname: name, Os: "linux", Distro: "Ubuntu 26.04", Kernel: "7.0.0", Arch: "amd64", CpuCount: 8, MemoryBytes: 16 << 30,
		Facts: map[string]string{"ips": "10.0.0.5"},
	}
}

func ctr(id, name, state string) *agentv1.Container {
	return &agentv1.Container{
		Runtime: agentv1.Runtime_RUNTIME_DOCKER, RuntimeId: id, Name: name, Image: "nginx:1.27", State: state, RestartCount: 1,
		Ports:  []*agentv1.PortMapping{{HostIp: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		Labels: map[string]string{"app": name}, CreatedAtUnixMs: 1790000000000,
	}
}

func snapshot(host *agentv1.HostFacts, cs ...*agentv1.Container) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Snapshot{Snapshot: &agentv1.InventorySnapshot{Host: host, Containers: cs}}}
}

func containerEvent(kind agentv1.ContainerChange_Kind, c *agentv1.Container) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Event{Event: &agentv1.InventoryEvent{
		Change: &agentv1.InventoryEvent_Container{Container: &agentv1.ContainerChange{Kind: kind, Container: c}},
	}}}
}

func hostEvent(h *agentv1.HostFacts) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Event{Event: &agentv1.InventoryEvent{
		Change: &agentv1.InventoryEvent_Host{Host: &agentv1.HostFactsChange{Host: h}},
	}}}
}

// drain returns the event types published so far (without blocking).
func drain(sub *inventory.Subscription) []string {
	var out []string
	for {
		select {
		case ev, ok := <-sub.C:
			if !ok {
				return out
			}
			out = append(out, ev.Type)
		default:
			return out
		}
	}
}

func subscribe(t *testing.T, svc *inventory.Service) *inventory.Subscription {
	t.Helper()
	sub, err := svc.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sub.Close)
	return sub
}

func TestINV1_SnapshotCreatesTheHostAndItsContainers(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	sub := subscribe(t, e.svc)

	e.svc.SetPresence(agent, true) // the stream comes up before the snapshot arrives
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1"), ctr("aaa111", "web", "running"), ctr("bbb222", "job", "exited")))

	host, ok := e.svc.Index().HostByAgent(agent)
	if !ok || host.Hostname != "web-1" || host.Status != inventory.StatusOnline || host.CPUCount != 8 || host.MemoryBytes != 16<<30 || host.Facts["ips"] != "10.0.0.5" || host.AgentID != agent {
		t.Fatalf("host = %+v", host)
	}
	page := e.svc.Index().Containers(inventory.ContainerFilter{HostID: host.ID}, "", 50)
	if len(page.Items) != 2 {
		t.Fatalf("%d containers, want 2", len(page.Items))
	}
	var web inventory.Container
	for _, c := range page.Items {
		if c.Name == "web" {
			web = c
		}
	}
	if web.Runtime != "docker" || web.State != "running" || web.RestartCount != 1 || len(web.Ports) != 1 || web.Ports[0].HostPort != 8080 || web.Labels["app"] != "web" || web.CreatedAt == nil || web.GoneAt != nil {
		t.Errorf("web = %+v", web)
	}
	if got := drain(sub); fmt.Sprint(got) != "[host.created container.created container.created]" {
		t.Errorf("events = %v", got)
	}
}

func TestInventorySurvivesARestart(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	e.svc.SetPresence(agent, true)
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1"), ctr("aaa111", "web", "running")))
	e.svc.HandleMessage(agent, containerEvent(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{RuntimeId: "aaa111"}))
	e.svc.HandleMessage(agent, containerEvent(agentv1.ContainerChange_KIND_CREATED, ctr("bbb222", "kept", "running")))

	again := e.newService() // a new process warms its index from the database
	h1, _ := e.svc.Index().HostByAgent(agent)
	h2, ok := again.Index().HostByAgent(agent)
	if !ok || h2.ID != h1.ID || h2.Hostname != "web-1" {
		t.Fatalf("host after restart = %+v", h2)
	}
	live := again.Index().Containers(inventory.ContainerFilter{}, "", 50)
	all := again.Index().Containers(inventory.ContainerFilter{IncludeGone: true}, "", 50)
	if len(live.Items) != 1 || live.Items[0].Name != "kept" || len(all.Items) != 2 {
		t.Errorf("after restart: %d live, %d total containers", len(live.Items), len(all.Items))
	}
}

func TestINV1_ASecondSnapshotReplacesTheState(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1"), ctr("a", "keep", "running"), ctr("b", "change", "running"), ctr("c", "vanish", "running")))
	sub := subscribe(t, e.svc)

	e.advance(time.Minute)
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1"), ctr("a", "keep", "running"), ctr("b", "change", "exited"), ctr("d", "new", "running")))

	got := drain(sub)
	want := map[string]int{"container.updated": 1, "container.removed": 1, "container.created": 1}
	counts := map[string]int{}
	for _, g := range got {
		counts[g]++
	}
	if fmt.Sprint(counts) != fmt.Sprint(want) {
		t.Errorf("events = %v, want one of each: %v", got, want)
	}
	host, _ := e.svc.Index().HostByAgent(agent)
	live := e.svc.Index().Containers(inventory.ContainerFilter{HostID: host.ID}, "", 50)
	names := []string{}
	for _, c := range live.Items {
		names = append(names, c.Name)
	}
	if len(names) != 3 || strings.Contains(strings.Join(names, ","), "vanish") {
		t.Errorf("live containers = %v", names)
	}
	gone := e.svc.Index().Containers(inventory.ContainerFilter{HostID: host.ID, IncludeGone: true}, "", 50)
	for _, c := range gone.Items {
		if (c.Name == "vanish") != (c.GoneAt != nil) {
			t.Errorf("%s: GoneAt = %v", c.Name, c.GoneAt)
		}
		if c.Name == "vanish" && !c.GoneAt.Equal(e.now()) {
			t.Errorf("gone at %v, want %v", c.GoneAt, e.now())
		}
	}
}

func TestINV2_ChangeEventsAreAppliedAndAnnounced(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()

	e.svc.HandleMessage(agent, containerEvent(agentv1.ContainerChange_KIND_CREATED, ctr("early", "early", "running")))
	if len(e.svc.Index().Containers(inventory.ContainerFilter{}, "", 50).Items) != 0 {
		t.Fatal("an event before any snapshot must wait for the snapshot")
	}
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1")))
	sub := subscribe(t, e.svc)

	steps := []struct {
		name string
		msg  *agentv1.AgentMessage
		want string
	}{
		{"create", containerEvent(agentv1.ContainerChange_KIND_CREATED, ctr("x1", "api", "created")), "container.created"},
		{"start", containerEvent(agentv1.ContainerChange_KIND_STARTED, ctr("x1", "api", "running")), "container.updated"},
		{"same again", containerEvent(agentv1.ContainerChange_KIND_UPDATED, ctr("x1", "api", "running")), ""},
		{"stop", containerEvent(agentv1.ContainerChange_KIND_STOPPED, ctr("x1", "api", "exited")), "container.updated"},
		{"remove", containerEvent(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{RuntimeId: "x1"}), "container.removed"},
		{"remove again", containerEvent(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{RuntimeId: "x1"}), ""},
		{"remove unknown", containerEvent(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{RuntimeId: "nope"}), ""},
		{"back again", containerEvent(agentv1.ContainerChange_KIND_CREATED, ctr("x1", "api", "running")), "container.created"},
	}
	var firstID string
	for _, s := range steps {
		start := time.Now()
		e.svc.HandleMessage(agent, s.msg)
		got := drain(sub)
		if s.want == "" && len(got) != 0 || s.want != "" && fmt.Sprint(got) != "["+s.want+"]" {
			t.Errorf("%s: events %v, want %q", s.name, got, s.want)
		}
		if time.Since(start) > time.Second {
			t.Errorf("%s took %v; INV-2 allows 10 s end to end", s.name, time.Since(start))
		}
		if s.name == "create" {
			firstID = e.svc.Index().Containers(inventory.ContainerFilter{}, "", 50).Items[0].ID
		}
	}
	items := e.svc.Index().Containers(inventory.ContainerFilter{IncludeGone: true}, "", 50).Items
	if len(items) != 1 || items[0].ID != firstID || items[0].GoneAt != nil || items[0].State != "running" {
		t.Errorf("a container that comes back keeps its row and clears gone: %+v", items)
	}
}

func TestHostFactChangesAreAnnouncedOnlyWhenTheyChange(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1")))
	sub := subscribe(t, e.svc)

	e.svc.HandleMessage(agent, hostEvent(hostFacts("web-1")))
	if got := drain(sub); len(got) != 0 {
		t.Errorf("unchanged facts announced %v", got)
	}
	changed := hostFacts("web-1")
	changed.Facts["ips"] = "10.0.0.5,192.0.2.9"
	changed.Kernel = "7.0.1"
	e.svc.HandleMessage(agent, hostEvent(changed))
	if got := drain(sub); fmt.Sprint(got) != "[host.updated]" {
		t.Errorf("changed facts announced %v", got)
	}
	if h, _ := e.svc.Index().HostByAgent(agent); h.Kernel != "7.0.1" || h.Facts["ips"] != "10.0.0.5,192.0.2.9" {
		t.Errorf("host = %+v", h)
	}
}

func TestAGT7_PresenceDrivesTheHostStatus(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	e.svc.SetPresence(agent, false) // before any host exists: nothing to update, nothing to fail
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1")))
	if h, _ := e.svc.Index().HostByAgent(agent); h.Status != inventory.StatusOffline {
		t.Fatalf("a host whose agent is not connected starts offline, got %s", h.Status)
	}
	sub := subscribe(t, e.svc)

	e.advance(time.Second)
	e.svc.SetPresence(agent, true)
	e.svc.SetPresence(agent, true) // repeating it changes nothing
	if h, _ := e.svc.Index().HostByAgent(agent); h.Status != inventory.StatusOnline || !h.LastSeenAt.Equal(e.now()) {
		t.Errorf("host = %+v", h)
	}
	e.svc.SetPresence(agent, false)
	if h, _ := e.svc.Index().HostByAgent(agent); h.Status != inventory.StatusOffline {
		t.Errorf("host = %+v", h)
	}
	if got := drain(sub); fmt.Sprint(got) != "[host.updated host.updated]" {
		t.Errorf("events = %v, want exactly one per real change", got)
	}

	again := e.newService()
	if h, _ := again.Index().HostByAgent(agent); h.Status != inventory.StatusOffline {
		t.Errorf("status after restart = %s", h.Status)
	}
}

func TestAgentsOnlyEverTouchTheirOwnHost(t *testing.T) {
	e := newEnv(t)
	a, b := e.agent(), e.agent()
	e.svc.HandleMessage(a, snapshot(hostFacts("host-a"), ctr("same-id", "on-a", "running")))
	e.svc.HandleMessage(b, snapshot(hostFacts("host-b"), ctr("same-id", "on-b", "running")))

	// B reports its container removed; A's container with the same runtime ID must be untouched.
	e.svc.HandleMessage(b, containerEvent(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{RuntimeId: "same-id"}))
	ha, _ := e.svc.Index().HostByAgent(a)
	hb, _ := e.svc.Index().HostByAgent(b)
	if ha.ID == hb.ID {
		t.Fatal("two agents share a host")
	}
	onA := e.svc.Index().Containers(inventory.ContainerFilter{HostID: ha.ID}, "", 50).Items
	onB := e.svc.Index().Containers(inventory.ContainerFilter{HostID: hb.ID}, "", 50).Items
	if len(onA) != 1 || onA[0].Name != "on-a" || len(onB) != 0 {
		t.Errorf("A has %v, B has %v", onA, onB)
	}
}

func TestAgentInputIsBoundedAndCleaned(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	long := strings.Repeat("é", 2000) // multi-byte on purpose: truncation must not split a rune

	bad := []*agentv1.Container{
		{Runtime: agentv1.Runtime_RUNTIME_DOCKER, RuntimeId: "../etc/passwd", Name: "path"},
		{Runtime: agentv1.Runtime_RUNTIME_DOCKER, RuntimeId: "", Name: "empty"},
		{Runtime: agentv1.Runtime_RUNTIME_UNSPECIFIED, RuntimeId: "unspec", Name: "unspecified"},
		{Runtime: agentv1.Runtime_RUNTIME_DOCKER, RuntimeId: strings.Repeat("a", 129), Name: "long id"},
		nil,
	}
	ugly := ctr("ugly", "na\x00me\n\x1b[31m"+long, "run\tning")
	ugly.Image = long
	ugly.Labels = map[string]string{}
	for i := range 200 {
		ugly.Labels[fmt.Sprintf("k%03d", i)] = long
	}
	ugly.Ports = []*agentv1.PortMapping{{HostPort: 70000, ContainerPort: 80, Protocol: "tcp"}, {HostPort: 1, ContainerPort: 1, Protocol: "<script>"}, {HostIp: "::", HostPort: 22, ContainerPort: 22, Protocol: "TCP"}}
	for range 400 {
		ugly.Ports = append(ugly.Ports, &agentv1.PortMapping{HostPort: 1, ContainerPort: 2, Protocol: "udp"})
	}
	hf := hostFacts(long)
	for i := range 200 {
		hf.Facts[fmt.Sprintf("f%03d", i)] = long
	}
	hf.CpuCount, hf.MemoryBytes = 1<<31, 1<<63

	e.svc.HandleMessage(agent, snapshot(hf, append(bad, ugly)...))
	e.svc.HandleMessage(agent, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Snapshot{Snapshot: &agentv1.InventorySnapshot{}}}) // no host at all: ignored

	host, ok := e.svc.Index().HostByAgent(agent)
	if !ok || len(host.Hostname) > 253 || len(host.Facts) > 64 || host.CPUCount < 0 || host.MemoryBytes < 0 {
		t.Fatalf("host = %d bytes name, %d facts, cpus %d, mem %d", len(host.Hostname), len(host.Facts), host.CPUCount, host.MemoryBytes)
	}
	for _, v := range host.Facts {
		if len(v) > 4096 {
			t.Fatal("an oversized fact survived")
		}
	}
	items := e.svc.Index().Containers(inventory.ContainerFilter{}, "", 50).Items
	if len(items) != 1 {
		t.Fatalf("%d containers stored, want only the one that can be identified", len(items))
	}
	c := items[0]
	if strings.ContainsAny(c.Name, "\x00\n\x1b") || c.State != "running" || len(c.Name) > 253 || len(c.Image) > 512 || len(c.Labels) != 64 {
		t.Errorf("container = name %q state %q image %d labels %d", c.Name, c.State, len(c.Image), len(c.Labels))
	}
	for _, v := range c.Labels {
		if len(v) > 512 {
			t.Fatal("an oversized label survived")
		}
	}
	if !validUTF8(c.Name) || !validUTF8(c.Image) || !validUTF8(host.Hostname) {
		t.Error("truncation split a multi-byte character")
	}
	if len(c.Ports) != 256 || c.Ports[0].Protocol != "tcp" && c.Ports[0].Protocol != "udp" {
		t.Errorf("ports = %d (first %+v), want the valid ones capped at 256", len(c.Ports), c.Ports[0])
	}
	if c.Ports[0].HostPort > 65535 {
		t.Error("an out-of-range port survived")
	}
}

func validUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func TestSnapshotsAreCappedAtTheContainerLimit(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	var list []*agentv1.Container
	for i := range 1600 {
		list = append(list, ctr(fmt.Sprintf("c%05d", i), fmt.Sprintf("n%d", i), "running"))
	}
	e.svc.HandleMessage(agent, snapshot(hostFacts("big"), append(list, list[0])...)) // plus a duplicate
	if n := len(e.svc.Index().Containers(inventory.ContainerFilter{}, "", 500).Items); n != 500 {
		t.Fatalf("first page = %d", n)
	}
	total := 0
	cursor := ""
	for {
		p := e.svc.Index().Containers(inventory.ContainerFilter{}, cursor, 500)
		total += len(p.Items)
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if total != 1500 {
		t.Errorf("%d containers stored, want the cap of 1500", total)
	}
}

func TestPaginationCoversEveryItemOnce(t *testing.T) {
	e := newEnv(t)
	for range 7 {
		e.svc.HandleMessage(e.agent(), snapshot(hostFacts("h")))
	}
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		p := e.svc.Index().Hosts(inventory.HostFilter{}, cursor, 3)
		pages++
		for _, h := range p.Items {
			if seen[h.ID] {
				t.Fatalf("host %s listed twice", h.ID)
			}
			seen[h.ID] = true
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 7 || pages != 3 {
		t.Errorf("%d hosts in %d pages, want 7 in 3", len(seen), pages)
	}
	if p := e.svc.Index().Hosts(inventory.HostFilter{Status: inventory.StatusOnline}, "", 50); len(p.Items) != 0 {
		t.Error("no host is online, but the filter returned some")
	}
	if p := e.svc.Index().Hosts(inventory.HostFilter{}, "ZZZZZZZZZZZZZZZZZZZZZZZZZZ", 5); len(p.Items) != 0 || p.NextCursor != "" {
		t.Errorf("a cursor past the end = %+v", p)
	}
}

func TestIndexReturnsCopies(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	e.svc.HandleMessage(agent, snapshot(hostFacts("h"), ctr("a", "web", "running")))
	h, _ := e.svc.Index().HostByAgent(agent)
	h.Facts["ips"] = "tampered"
	c := e.svc.Index().Containers(inventory.ContainerFilter{}, "", 5).Items[0]
	c.Labels["app"] = "tampered"
	c.Ports[0].HostPort = 1

	h2, _ := e.svc.Index().HostByAgent(agent)
	c2 := e.svc.Index().Containers(inventory.ContainerFilter{}, "", 5).Items[0]
	if h2.Facts["ips"] == "tampered" || c2.Labels["app"] == "tampered" || c2.Ports[0].HostPort == 1 {
		t.Error("a caller changed the index through a returned value")
	}
}

func TestHubDeliversInOrderAndNeverBlocksThePublisher(t *testing.T) {
	hub := inventory.NewHub()
	fast, _ := hub.Subscribe()
	slow, _ := hub.Subscribe()
	defer fast.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 { // far more than a subscriber buffers, with nobody reading `slow`
			hub.Publish(inventory.EventContainerUpdated, i)
			if len(fast.C) > 40 {
				<-fast.C
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}

	var types []string
	var last uint64
	for ev := range slow.C { // closed by the hub once it fell behind
		if ev.Seq <= last {
			t.Errorf("sequence went backwards: %d after %d", ev.Seq, last)
		}
		last = ev.Seq
		types = append(types, ev.Type)
	}
	if len(types) == 0 || types[len(types)-1] != inventory.EventResync {
		t.Errorf("a subscriber that fell behind must end with a resync event, got %d events ending in %q", len(types), types[len(types)-1])
	}
	slow.Close() // closing twice is harmless
	slow.Close()
}

func TestHubLimitsSubscribers(t *testing.T) {
	hub := inventory.NewHub()
	var subs []*inventory.Subscription
	for range inventory.MaxSubscribers {
		s, err := hub.Subscribe()
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, s)
	}
	if _, err := hub.Subscribe(); err != inventory.ErrTooManySubscribers {
		t.Errorf("err = %v", err)
	}
	subs[0].Close()
	if s, err := hub.Subscribe(); err != nil {
		t.Errorf("a freed slot was not reusable: %v", err)
	} else {
		s.Close()
	}
}

func TestContainersWithoutACreationTimeAreStored(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	noTime := ctr("nt", "no-time", "running")
	noTime.CreatedAtUnixMs = 0
	e.svc.HandleMessage(agent, snapshot(hostFacts("h"), noTime))

	items := e.svc.Index().Containers(inventory.ContainerFilter{}, "", 5).Items
	if len(items) != 1 || items[0].CreatedAt != nil {
		t.Fatalf("items = %+v", items)
	}
	again := e.newService() // and it reloads from the database
	if got := again.Index().Containers(inventory.ContainerFilter{}, "", 5).Items; len(got) != 1 || got[0].CreatedAt != nil {
		t.Errorf("after restart = %+v", got)
	}
}
