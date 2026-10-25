// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/agent/inventory"
	"github.com/nuxdeck/nuxdeck/internal/agent/run"
	"github.com/nuxdeck/nuxdeck/internal/agent/sockguard"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// fakeDocker is a minimal Docker API behind the real nux-sockguard.
type fakeDocker struct {
	mu      sync.Mutex
	inspect map[string]string
	events  chan string
}

func startDockerBehindSockguard(t *testing.T) (guardSock string, d *fakeDocker) {
	t.Helper()
	dir, err := os.MkdirTemp("", "invt") // short path: unix sockets are limited to ~108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	d = &fakeDocker{inspect: map[string]string{}, events: make(chan string, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Platform":{"Name":"Docker Engine - Community"}}`)
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		var items []string
		for id := range d.inspect {
			items = append(items, fmt.Sprintf(`{"Id":%q}`, id))
		}
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	})
	mux.HandleFunc("/containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		body, ok := d.inspect[r.PathValue("id")]
		d.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case l := <-d.events:
				_, _ = fmt.Fprintln(w, l)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	dockerSock := filepath.Join(dir, "d.sock")
	dln, err := net.Listen("unix", dockerSock)
	if err != nil {
		t.Fatal(err)
	}
	dsrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = dsrv.Serve(dln) }()
	t.Cleanup(func() { _ = dsrv.Close() })

	guardSock = filepath.Join(dir, "g.sock")
	gln, err := sockguard.Listen(guardSock, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sockguard.New(sockguard.Config{Upstream: dockerSock, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Serve(ctx, gln)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return guardSock, d
}

func (d *fakeDocker) set(id, body string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inspect[id] = body
}

func dockerInspect(id, name, state string) string {
	return fmt.Sprintf(`{"Id":%q,"Name":"/%s","Created":"2026-10-25T10:00:00Z","RestartCount":0,"State":{"Status":%q},
 "Config":{"Image":"nginx:1.27","Env":["DB_PASSWORD=SECRET_VALUE"],"Labels":{"app":%q}},"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}}}`, id, name, state, name)
}

func (e *env) nextMessage(match func(*agentv1.AgentMessage) bool, within time.Duration) *agentv1.AgentMessage {
	e.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case m := <-e.msgs:
			if match(m) {
				return m
			}
		case <-deadline:
			e.t.Fatal("the expected message never reached the gateway")
			return nil
		}
	}
}

// INV-1 and INV-2 across the whole chain: runtime, nux-sockguard, collector, agent, mTLS stream, gateway.
func TestINV_InventoryReachesTheGatewayThroughSockguard(t *testing.T) {
	e := newEnv(t)
	guardSock, docker := startDockerBehindSockguard(t)
	docker.set("aaa111", dockerInspect("aaa111", "web", "running"))

	dir := t.TempDir()
	id := e.enrollAgent(dir)
	inv := inventory.New(inventory.Config{SockguardSocket: guardSock, ReconnectDelay: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go inv.Run(ctx)
	r := e.runAgent(dir, func(c *run.Config) { c.Inventory = inv })
	defer r.stop()
	e.wantPresence(id, true, 5*time.Second)

	// The snapshot arrives first and holds the host and the existing container.
	var snap *agentv1.InventorySnapshot
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		m := e.nextMessage(func(m *agentv1.AgentMessage) bool { return m.GetSnapshot() != nil }, 5*time.Second)
		if snap = m.GetSnapshot(); len(snap.Containers) == 1 {
			break
		}
	}
	if snap == nil || snap.Host.GetHostname() == "" || snap.Host.GetKernel() == "" || snap.Host.GetMemoryBytes() == 0 || snap.Host.GetCpuCount() == 0 {
		t.Fatalf("snapshot host = %v", snap.GetHost())
	}
	if len(snap.Containers) != 1 {
		// The container list can arrive as a change right after a first, host-only snapshot.
		ev := e.nextMessage(func(m *agentv1.AgentMessage) bool { return m.GetEvent().GetContainer() != nil }, 5*time.Second)
		snap.Containers = append(snap.Containers, ev.GetEvent().GetContainer().Container)
	}
	web := snap.Containers[0]
	if web.Name != "web" || web.State != "running" || web.Runtime != agentv1.Runtime_RUNTIME_DOCKER || len(web.Ports) != 1 || web.Ports[0].HostPort != 8080 {
		t.Errorf("container = %v", web)
	}

	// A change on the host reaches the gateway quickly (INV-2 allows 10 s end to end).
	started := time.Now()
	docker.set("bbb222", dockerInspect("bbb222", "worker", "running"))
	docker.events <- `{"Type":"container","Action":"start","Actor":{"ID":"bbb222","Attributes":{"name":"worker"}}}`
	m := e.nextMessage(func(m *agentv1.AgentMessage) bool {
		c := m.GetEvent().GetContainer()
		return c != nil && c.Container.GetRuntimeId() == "bbb222"
	}, 8*time.Second)
	if took := time.Since(started); took > 5*time.Second {
		t.Errorf("the change took %v to reach the gateway", took)
	}
	if k := m.GetEvent().GetContainer().Kind; k != agentv1.ContainerChange_KIND_CREATED {
		t.Errorf("a container the agent had not seen arrives as %v, want CREATED", k)
	}

	// Nothing secret crossed the wire anywhere in the chain.
	for len(e.msgs) > 0 {
		if s := fmt.Sprint(<-e.msgs); strings.Contains(s, "SECRET_VALUE") {
			t.Fatalf("a secret reached the gateway: %s", s)
		}
	}
}

func TestINV_AMissingRuntimeShowsUpInHeartbeats(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	id := e.enrollAgent(dir)
	inv := inventory.New(inventory.Config{SockguardSocket: filepath.Join(os.TempDir(), "no-such-sockguard.sock"), RetryInterval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go inv.Run(ctx)
	r := e.runAgent(dir, func(c *run.Config) { c.Inventory = inv })
	defer r.stop()
	e.wantPresence(id, true, 5*time.Second)

	snap := e.nextMessage(func(m *agentv1.AgentMessage) bool { return m.GetSnapshot() != nil }, 5*time.Second).GetSnapshot()
	if snap.Host.GetHostname() == "" {
		t.Error("host facts must still be reported when containers are unavailable")
	}
	e.nextMessage(func(m *agentv1.AgentMessage) bool {
		for _, ce := range m.GetHeartbeat().GetStats().GetCollectorErrors() {
			if ce.Collector == "containers" && ce.Code == "AGT-COL-001" {
				return true
			}
		}
		return false
	}, 5*time.Second)
}
