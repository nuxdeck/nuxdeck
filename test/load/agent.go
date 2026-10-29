// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"github.com/nuxdeck/nuxdeck/internal/agent/enroll"
	"github.com/nuxdeck/nuxdeck/internal/agent/identity"
	"github.com/nuxdeck/nuxdeck/internal/agent/link"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// protocolVersion matches internal/agent/run; it is unexported there, so it is repeated here.
const protocolVersion = 1

// The server's defaults, used when HelloAck does not carry an interval. The agent's own
// run package uses the same values (10 s heartbeat, 15 s collection).
const (
	defaultHeartbeat = 10 * time.Second
	defaultMetric    = 15 * time.Second
	inventoryEvery   = 60 * time.Second
)

// fleetStats counts what the simulated agents did. Every field is updated concurrently.
type fleetStats struct {
	connected     atomic.Int64
	metricBatches atomic.Uint64
	heartbeats    atomic.Uint64
	events        atomic.Uint64
	streamErrors  atomic.Uint64
}

// simAgent is one enrolled, simulated agent. It speaks the real agent protocol over the real
// mutual-TLS link, but its inventory and metrics are generated, so 200 agents cost one process.
type simAgent struct {
	name       string
	dir        string
	containers int
	timeScale  float64
	stats      *fleetStats
}

// enrolAgent trades a single-use token for an identity in dir.
func enrolAgent(ctx context.Context, token, dir, name string) error {
	_, err := enroll.Do(ctx, enroll.Request{
		StateDir: dir, Token: token, Version: "load-sim", Hostname: name, OS: "linux", Arch: "amd64",
	})
	if err != nil {
		return fmt.Errorf("enrol %s: %w", name, err)
	}
	return nil
}

// run keeps the agent connected until ctx ends. A stream that breaks is recorded and returned;
// the harness treats any break as a failure rather than hiding it behind a reconnect.
func (a *simAgent) run(ctx context.Context) error {
	id, err := identity.Load(a.dir)
	if err != nil {
		return fmt.Errorf("load identity %s: %w", a.name, err)
	}
	conn, err := link.Mutual(id)
	if err != nil {
		return fmt.Errorf("dial %s: %w", a.name, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := agentv1.NewAgentGatewayClient(conn).Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect %s: %w", a.name, err)
	}
	if err := stream.Send(a.hello()); err != nil {
		return fmt.Errorf("hello %s: %w", a.name, err)
	}
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("await HelloAck %s: %w", a.name, err)
	}
	ack := first.GetHelloAck()
	if ack == nil {
		return fmt.Errorf("%s: first server message was %T, not HelloAck", a.name, first.GetBody())
	}
	if err := stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Snapshot{Snapshot: a.snapshot()}}); err != nil {
		return fmt.Errorf("snapshot %s: %w", a.name, err)
	}

	a.stats.connected.Add(1)
	defer a.stats.connected.Add(-1)
	recvErr := make(chan error, 1)
	go drain(stream, recvErr)
	return a.loop(ctx, stream, ack, recvErr)
}

func (a *simAgent) loop(ctx context.Context, stream grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ServerMessage], ack *agentv1.HelloAck, recvErr <-chan error) error {
	metricTick := time.NewTicker(a.scaled(seconds(ack.GetMetricIntervalSeconds(), defaultMetric)))
	defer metricTick.Stop()
	heartbeatTick := time.NewTicker(a.scaled(seconds(ack.GetHeartbeatIntervalSeconds(), defaultHeartbeat)))
	defer heartbeatTick.Stop()
	inventoryTick := time.NewTicker(a.scaled(inventoryEvery))
	defer inventoryTick.Stop()

	rng := rand.New(rand.NewPCG(uint64(len(a.name)), uint64(a.containers))) //nolint:gosec // load generator, not security-sensitive
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-recvErr:
			if ctx.Err() != nil {
				return nil
			}
			a.stats.streamErrors.Add(1)
			return fmt.Errorf("stream %s ended: %w", a.name, err)
		case now := <-metricTick.C:
			seq++
			if err := stream.Send(a.metrics(now, seq, rng)); err != nil {
				return a.sendErr(ctx, err)
			}
			a.stats.metricBatches.Add(1)
		case now := <-heartbeatTick.C:
			if err := stream.Send(a.heartbeat(now)); err != nil {
				return a.sendErr(ctx, err)
			}
			a.stats.heartbeats.Add(1)
		case now := <-inventoryTick.C:
			if err := stream.Send(a.containerUpdate(now, seq)); err != nil {
				return a.sendErr(ctx, err)
			}
			a.stats.events.Add(1)
		}
	}
}

// sendErr maps a send failure to nil when the harness is shutting down, so teardown is not counted as a fault.
func (a *simAgent) sendErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	a.stats.streamErrors.Add(1)
	return fmt.Errorf("send %s: %w", a.name, err)
}

func drain(stream grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ServerMessage], out chan<- error) {
	for {
		if _, err := stream.Recv(); err != nil {
			out <- err
			return
		}
	}
}

func (a *simAgent) scaled(d time.Duration) time.Duration {
	return time.Duration(float64(d) / a.timeScale)
}

func seconds(v uint32, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return time.Duration(v) * time.Second
}

func (a *simAgent) hello() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: protocolVersion, AgentVersion: "load-sim", Hostname: a.name, Os: "linux", Arch: "amd64",
	}}}
}

func (a *simAgent) runtimeID(i int) string {
	return fmt.Sprintf("%s-c%03d", a.name, i)
}

func (a *simAgent) container(i int, restarts uint32) *agentv1.Container {
	hostPort := uint32(20000 + i) //nolint:gosec // simulated port numbers are small and positive
	return &agentv1.Container{
		Runtime: agentv1.Runtime_RUNTIME_DOCKER, RuntimeId: a.runtimeID(i), Name: fmt.Sprintf("svc-%02d", i),
		Image: "ghcr.io/nuxdeck/load-sim:1", State: "running", RestartCount: restarts,
		Ports:           []*agentv1.PortMapping{{HostIp: "0.0.0.0", HostPort: hostPort, ContainerPort: 8080, Protocol: "tcp"}},
		CreatedAtUnixMs: time.Now().Add(-time.Hour).UnixMilli(),
	}
}

func (a *simAgent) snapshot() *agentv1.InventorySnapshot {
	snap := &agentv1.InventorySnapshot{
		Host: &agentv1.HostFacts{
			Hostname: a.name, Os: "linux", Distro: "Ubuntu 24.04", Kernel: "6.8.0", Arch: "amd64",
			CpuCount: 4, MemoryBytes: 8 << 30,
		},
		TakenAtUnixMs: time.Now().UnixMilli(),
	}
	for i := range a.containers {
		snap.Containers = append(snap.Containers, a.container(i, 0))
	}
	return snap
}

func (a *simAgent) containerUpdate(now time.Time, seq uint64) *agentv1.AgentMessage {
	c := a.container(0, uint32(seq%3))
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Event{Event: &agentv1.InventoryEvent{
		AtUnixMs: now.UnixMilli(),
		Change: &agentv1.InventoryEvent_Container{Container: &agentv1.ContainerChange{
			Kind: agentv1.ContainerChange_KIND_UPDATED, Container: c,
		}},
	}}}
}

// metrics builds one batch in the shape of a real 15 s collection: host series plus two per container.
func (a *simAgent) metrics(now time.Time, seq uint64, rng *rand.Rand) *agentv1.AgentMessage {
	ts := now.UnixMilli()
	point := func(v float64) []*agentv1.Point { return []*agentv1.Point{{TsUnixMs: ts, Value: v}} }
	host := &agentv1.Target{Kind: agentv1.TargetKind_TARGET_KIND_HOST}
	batch := &agentv1.MetricBatch{Series: []*agentv1.Series{
		{Target: host, Metric: "nux_host_cpu_usage_ratio", Points: point(0.05 + rng.Float64()*0.2)},
		{Target: host, Metric: "nux_host_load_average", Labels: map[string]string{"window": "1m"}, Points: point(0.5 + rng.Float64())},
		{Target: host, Metric: "nux_host_memory_bytes", Labels: map[string]string{"type": "used"}, Points: point(float64(2<<30) + rng.Float64()*1e8)},
		{Target: host, Metric: "nux_host_network_bytes_total", Labels: map[string]string{"interface": "eth0", "direction": "rx"}, Points: point(float64(seq) * 15000)},
	}}
	for i := range a.containers {
		target := &agentv1.Target{Kind: agentv1.TargetKind_TARGET_KIND_CONTAINER, Id: a.runtimeID(i)}
		batch.Series = append(batch.Series,
			&agentv1.Series{Target: target, Metric: "nux_container_cpu_usage_ratio", Points: point(rng.Float64() * 0.1)},
			&agentv1.Series{Target: target, Metric: "nux_container_memory_bytes", Points: point(float64(64<<20) + rng.Float64()*1e6)},
		)
	}
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Metrics{Metrics: batch}}
}

func (a *simAgent) heartbeat(now time.Time) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		SentAtUnixMs: now.UnixMilli(),
		Stats:        &agentv1.AgentStats{MemoryBytes: 30 << 20, CpuPercent: 0.2},
	}}}
}

// fleet owns the simulated agents of one run and their goroutines.
type fleet struct {
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stats      fleetStats
	agents     int
	containers int
	timeScale  float64
	workDir    string
	errs       chan error
}

func newFleet(parent context.Context, workDir string, containers int, timeScale float64) *fleet {
	ctx, cancel := context.WithCancel(parent)
	return &fleet{ctx: ctx, cancel: cancel, containers: containers, timeScale: timeScale, workDir: workDir, errs: make(chan error, 1024)}
}

// grow enrols and connects n more agents; enrolment runs in parallel with a bounded width.
func (f *fleet) grow(n int, token func(context.Context) (string, error)) error {
	const enrolWidth = 8
	sem := make(chan struct{}, enrolWidth)
	var enrolWG sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	fail := func(err error) {
		errMu.Lock()
		defer errMu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}
	for range n {
		idx := f.agents
		f.agents++
		name := fmt.Sprintf("sim-%03d", idx)
		tok, err := token(f.ctx)
		if err != nil {
			return err
		}
		a := &simAgent{name: name, dir: fmt.Sprintf("%s/agents/%s", f.workDir, name), containers: f.containers, timeScale: f.timeScale, stats: &f.stats}
		enrolWG.Add(1)
		sem <- struct{}{}
		go func() {
			defer enrolWG.Done()
			defer func() { <-sem }()
			if err := enrolAgent(f.ctx, tok, a.dir, name); err != nil {
				fail(err)
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				if err := a.run(f.ctx); err != nil {
					select {
					case f.errs <- err:
					default:
					}
				}
			}()
		}()
	}
	enrolWG.Wait()
	return firstErr
}

// stop ends every agent connection and waits for the goroutines to return.
func (f *fleet) stop() {
	f.cancel()
	f.wg.Wait()
}

// firstStreamError returns one recorded agent failure without blocking.
func (f *fleet) firstStreamError() error {
	select {
	case err := <-f.errs:
		return err
	default:
		return nil
	}
}
