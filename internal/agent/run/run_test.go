// SPDX-License-Identifier: Apache-2.0

package run

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/nuxdeck/nuxdeck/internal/agent/identity"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const wait = 10 * time.Second

// fakeGateway is an in-process gRPC gateway with mutual TLS, so session() runs unchanged.
type fakeGateway struct {
	agentv1.UnimplementedAgentGatewayServer
	ack   *agentv1.HelloAck
	conns chan *fakeConn
}

// fakeConn is the server end of one agent stream.
type fakeConn struct {
	in   chan *agentv1.AgentMessage // everything the agent sent after Hello
	out  chan *agentv1.ServerMessage
	end  chan struct{} // closing it makes the server end the stream
	once sync.Once
}

func (c *fakeConn) drop() { c.once.Do(func() { close(c.end) }) }

func (g *fakeGateway) Connect(s grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	if _, err := s.Recv(); err != nil { // Hello
		return err
	}
	if err := s.Send(&agentv1.ServerMessage{Body: &agentv1.ServerMessage_HelloAck{HelloAck: g.ack}}); err != nil {
		return err
	}
	c := &fakeConn{in: make(chan *agentv1.AgentMessage, 64), out: make(chan *agentv1.ServerMessage, 8), end: make(chan struct{})}
	go func() {
		for {
			m, err := s.Recv()
			if err != nil {
				return
			}
			c.in <- m
		}
	}()
	g.conns <- c
	for {
		select {
		case m := <-c.out:
			if err := s.Send(m); err != nil {
				return err
			}
		case <-c.end:
			return nil
		case <-s.Context().Done():
			return nil
		}
	}
}

// startAgent enrols a throwaway identity against a fake gateway and runs the loop.
func startAgent(t *testing.T, ack *agentv1.HelloAck, m Metrics, now time.Time) *fakeGateway {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leaf := func(serial int64, eku x509.ExtKeyUsage, ips []net.IP) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"}, IPAddresses: ips, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{eku}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	srvDER, srvKey := leaf(2, x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	agentDER, agentKey := leaf(3, x509.ExtKeyUsageClientAuth, nil)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
	})))
	gw := &fakeGateway{ack: ack, conns: make(chan *fakeConn, 4)}
	agentv1.RegisterAgentGatewayServer(srv, gw)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()

	dir := t.TempDir()
	if err := identity.Save(dir, "agent-1", "https://"+ln.Addr().String(), caDER, agentDER, agentKey); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			StateDir: dir, Version: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Heartbeat: time.Hour, Now: func() time.Time { return now },
			Backoff: &Backoff{Min: 10 * time.Millisecond, Max: 20 * time.Millisecond},
			Metrics: m, RenewAt: func(*identity.Identity) time.Time { return now.Add(24 * time.Hour) },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v", err)
			}
		case <-time.After(wait):
			t.Error("Run did not stop")
		}
		srv.Stop()
	})
	return gw
}

func (g *fakeGateway) accept(t *testing.T) *fakeConn {
	t.Helper()
	select {
	case c := <-g.conns:
		return c
	case <-time.After(wait):
		t.Fatal("agent did not connect")
		return nil
	}
}

func (c *fakeConn) metrics(t *testing.T) *agentv1.MetricBatch {
	t.Helper()
	select {
	case m := <-c.in:
		if m.GetMetrics() == nil {
			t.Fatalf("expected a MetricBatch, got %T", m.GetBody())
		}
		return m.GetMetrics()
	case <-time.After(wait):
		t.Fatal("no MetricBatch arrived")
		return nil
	}
}

// fakeMetrics mimics the agent's ring buffer: Next marks samples older than the cut as replayed.
type fakeMetrics struct {
	mu        sync.Mutex
	queue     []fakeBatch
	intervals []uint32
	cuts      []time.Time
	committed int
	held      bool // while set, Next reports an empty buffer (the sender is not draining)
	notify    chan struct{}
}

type fakeBatch struct {
	metric string
	at     time.Time
}

func newFakeMetrics() *fakeMetrics { return &fakeMetrics{notify: make(chan struct{}, 1)} }

func (f *fakeMetrics) push(metric string, at time.Time) {
	f.mu.Lock()
	f.queue = append(f.queue, fakeBatch{metric, at})
	f.mu.Unlock()
	select {
	case f.notify <- struct{}{}:
	default:
	}
}

func (f *fakeMetrics) SetInterval(s uint32) {
	f.mu.Lock()
	f.intervals = append(f.intervals, s)
	f.mu.Unlock()
}
func (f *fakeMetrics) Notify() <-chan struct{}           { return f.notify }
func (f *fakeMetrics) Errors() []*agentv1.CollectorError { return nil }

func (f *fakeMetrics) Next(replayBefore time.Time) (*agentv1.MetricBatch, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cuts = append(f.cuts, replayBefore)
	if f.held || len(f.queue) == 0 {
		return nil, nil
	}
	b := f.queue[0]
	batch := &agentv1.MetricBatch{
		Replayed: b.at.Before(replayBefore),
		Series:   []*agentv1.Series{{Metric: b.metric, Points: []*agentv1.Point{{TsUnixMs: b.at.UnixMilli(), Value: 1}}}},
	}
	return batch, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queue = f.queue[1:]
		f.committed++
	}
}

func (f *fakeMetrics) hold(on bool) {
	f.mu.Lock()
	f.held = on
	f.mu.Unlock()
	if !on {
		select {
		case f.notify <- struct{}{}:
		default:
		}
	}
}

func (f *fakeMetrics) snapshot() (intervals []uint32, committed int, queued int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.intervals), f.committed, len(f.queue)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMET1_ReplayedBatchesThenLiveBatchesAreSent(t *testing.T) {
	now := time.Now()
	m := newFakeMetrics()
	m.push("buffered.one", now.Add(-5*time.Minute)) // taken while offline
	m.push("buffered.two", now.Add(-time.Minute))
	gw := startAgent(t, &agentv1.HelloAck{ProtocolVersion: 1, HeartbeatIntervalSeconds: 60, MetricIntervalSeconds: 15}, m, now)
	c := gw.accept(t)

	for _, want := range []string{"buffered.one", "buffered.two"} {
		b := c.metrics(t)
		if !b.GetReplayed() || b.GetSeries()[0].GetMetric() != want {
			t.Fatalf("got replayed=%v metric=%q, want replayed buffered batch %q", b.GetReplayed(), b.GetSeries()[0].GetMetric(), want)
		}
	}

	m.push("live", now.Add(time.Second)) // sampled after the connection
	if b := c.metrics(t); b.GetReplayed() || b.GetSeries()[0].GetMetric() != "live" {
		t.Fatalf("live batch: replayed=%v metric=%q", b.GetReplayed(), b.GetSeries()[0].GetMetric())
	}
	waitFor(t, "all three batches committed", func() bool { _, committed, queued := m.snapshot(); return committed == 3 && queued == 0 })

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cut := range m.cuts {
		if !cut.Equal(now) {
			t.Errorf("replay cut = %v, want the connection time %v", cut, now)
		}
	}
}

func TestMET1_BatchesBufferedWhileOfflineAreReplayedAfterReconnect(t *testing.T) {
	now := time.Now()
	m := newFakeMetrics()
	gw := startAgent(t, &agentv1.HelloAck{ProtocolVersion: 1, HeartbeatIntervalSeconds: 60, MetricIntervalSeconds: 15}, m, now)
	first := gw.accept(t)
	m.push("online", now.Add(time.Second))
	if b := first.metrics(t); b.GetReplayed() {
		t.Fatal("a sample taken while connected must not be flagged replayed")
	}

	// Samples taken while the link is down pile up in the buffer; hold the sender so the
	// old connection cannot take them before it notices the drop.
	m.hold(true)
	m.push("while.offline", now.Add(-30*time.Second))
	first.drop()
	second := gw.accept(t)
	m.hold(false)
	if b := second.metrics(t); !b.GetReplayed() || b.GetSeries()[0].GetMetric() != "while.offline" {
		t.Fatalf("after reconnect: replayed=%v metric=%q", b.GetReplayed(), b.GetSeries()[0].GetMetric())
	}
}

func TestMET1_HelloAckAndConfigUpdateSetTheSamplingInterval(t *testing.T) {
	now := time.Now()
	m := newFakeMetrics()
	gw := startAgent(t, &agentv1.HelloAck{ProtocolVersion: 1, HeartbeatIntervalSeconds: 60, MetricIntervalSeconds: 15}, m, now)
	c := gw.accept(t)

	waitFor(t, "HelloAck interval applied", func() bool { got, _, _ := m.snapshot(); return slices.Equal(got, []uint32{15}) })
	c.out <- &agentv1.ServerMessage{Body: &agentv1.ServerMessage_Config{Config: &agentv1.ConfigUpdate{MetricIntervalSeconds: 30}}}
	waitFor(t, "ConfigUpdate applied", func() bool { got, _, _ := m.snapshot(); return slices.Equal(got, []uint32{15, 30}) })

	c.out <- &agentv1.ServerMessage{Body: &agentv1.ServerMessage_Config{Config: &agentv1.ConfigUpdate{MetricIntervalSeconds: 0}}}
	waitFor(t, "zero (default) interval applied", func() bool { got, _, _ := m.snapshot(); return slices.Equal(got, []uint32{15, 30, 0}) })
}
