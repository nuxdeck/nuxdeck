// SPDX-License-Identifier: Apache-2.0

// Package run is the agent's main loop: it keeps one stream to nuxd alive, sends
// heartbeats, renews the certificate and reconnects with backoff.
package run

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nuxdeck/nuxdeck/internal/agent/identity"
	"github.com/nuxdeck/nuxdeck/internal/agent/link"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	protocolVersion   = 1
	defaultHeartbeat  = 10 * time.Second
	ackTimeout        = 10 * time.Second
	renewRetry        = 30 * time.Second
	maxCertRejections = 5
)

// Inventory is the agent's view of its host and containers; *inventory.Collector implements it.
type Inventory interface {
	// Attach returns the current state and the changes that follow it. The channel is closed if
	// the caller falls behind, in which case it attaches again.
	Attach() (*agentv1.InventorySnapshot, <-chan *agentv1.InventoryEvent, func())
	// Errors lists the collectors that currently fail.
	Errors() []*agentv1.CollectorError
}

// Metrics is the agent's metric source; *metrics.Service implements it.
type Metrics interface {
	// SetInterval applies the server's collection interval in seconds (0 means the default).
	SetInterval(seconds uint32)
	// Next returns the oldest unsent batch, marking samples older than replayBefore as
	// replayed, and a commit to call once it was sent. A nil batch means nothing is waiting.
	Next(replayBefore time.Time) (*agentv1.MetricBatch, func())
	// Notify fires when new samples are buffered.
	Notify() <-chan struct{}
	// Errors lists the metric collectors that currently fail.
	Errors() []*agentv1.CollectorError
}

// Logs serves live log streams on the server's request; *logs.Manager implements it.
type Logs interface {
	Open(ctx context.Context, o *agentv1.OpenLogStream)
	Close(streamID string)
	// CloseAll stops every stream; it is called when the connection ends.
	CloseAll()
	// Out yields LogChunk and LogStreamEnded messages; the loop sends them at the pace of the link.
	Out() <-chan *agentv1.AgentMessage
}

// Checks runs uptime checks on the server's request; *checks.Manager implements it.
type Checks interface {
	Run(ctx context.Context, rc *agentv1.RunCheck)
	// CloseAll waits for running checks; it is called when the connection ends.
	CloseAll()
	// Out yields CheckResult messages.
	Out() <-chan *agentv1.AgentMessage
}

// Config is what the loop needs.
type Config struct {
	StateDir string
	Version  string
	Log      *slog.Logger
	// Heartbeat overrides the interval the server asks for; tests shorten it.
	Heartbeat time.Duration
	// Backoff overrides the reconnect delays; tests shorten them.
	Backoff *Backoff
	// Now supplies the clock; nil means time.Now.
	Now func() time.Time
	// Inventory, when set, is sent as a snapshot after every connect and then as change events.
	Inventory Inventory
	// Metrics, when set, is drained onto the stream: buffered samples replayed after a connect, then live.
	Metrics Metrics
	// Logs, when set, answers OpenLogStream and CloseLogStream requests.
	Logs Logs
	// Checks, when set, answers RunCheck requests.
	Checks Checks
	// RenewAt overrides when to renew (default: two thirds into the certificate's life); tests use it.
	RenewAt func(*identity.Identity) time.Time
}

func (c Config) renewAt(id *identity.Identity) time.Time {
	if c.RenewAt != nil {
		return c.RenewAt(id)
	}
	return id.RenewAt()
}

// Run connects to nuxd and stays connected until ctx ends. It returns nil on a
// requested stop. It returns a coded error when retrying cannot help: the agent was
// revoked, its identity is unusable, or its certificate expired while offline.
func Run(ctx context.Context, c Config) error {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Backoff == nil {
		c.Backoff = &Backoff{}
	}
	rejections := 0
	for {
		id, err := identity.Load(c.StateDir)
		if err != nil {
			return err
		}
		if !c.Now().Before(id.Leaf.NotAfter) {
			return errcode.New(errcode.AGTID002, "the certificate expired at %s", id.Leaf.NotAfter.Format(time.RFC3339))
		}

		started := c.Now()
		err = session(ctx, c, id)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, errRevoked):
			return errcode.New(errcode.AGTRev001, "nuxd revoked this agent")
		}

		// A certificate that fails the handshake every time is revoked or unknown to the server.
		if err != nil && strings.Contains(err.Error(), "bad certificate") {
			if rejections++; rejections >= maxCertRejections {
				return errcode.New(errcode.AGTRev001, "nuxd rejected the agent certificate %d times in a row", rejections)
			}
		} else {
			rejections = 0
		}
		if c.Now().Sub(started) >= stableAfter {
			c.Backoff.Reset()
		}
		wait := c.Backoff.Next()
		c.Log.Warn("connection to nuxd lost; retrying", "in", wait.Round(time.Millisecond), "error", err)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
	}
}

var errRevoked = errors.New("agent revoked")

// session runs one connection until it fails or the context ends.
func session(ctx context.Context, c Config, id *identity.Identity) error {
	conn, err := link.Mutual(id)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := agentv1.NewAgentGatewayClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(hello(c.Version)); err != nil {
		return err
	}

	in := make(chan *agentv1.ServerMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case in <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	interval := defaultHeartbeat
	select {
	case m := <-in:
		ack := m.GetHelloAck()
		if ack == nil {
			return classifyServerMessage(m, errors.New("the server's first message was not HelloAck"))
		}
		if s := time.Duration(ack.GetHeartbeatIntervalSeconds()) * time.Second; s > 0 {
			interval = s
		}
		if c.Metrics != nil {
			c.Metrics.SetInterval(ack.GetMetricIntervalSeconds())
		}
	case err := <-recvErr:
		return classifyStreamError(err)
	case <-time.After(ackTimeout):
		return errors.New("no HelloAck from the server")
	case <-ctx.Done():
		return nil
	}
	if c.Heartbeat > 0 {
		interval = c.Heartbeat
	}
	c.Log.Info("connected to nuxd", "agent_id", id.AgentID, "heartbeat", interval.String())

	var changes <-chan *agentv1.InventoryEvent // nil without an inventory: that case never fires
	detach := func() {}
	defer func() { detach() }()
	attach := func() error {
		detach()
		var snap *agentv1.InventorySnapshot
		snap, changes, detach = c.Inventory.Attach()
		return stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Snapshot{Snapshot: snap}})
	}
	if c.Inventory != nil {
		if err := attach(); err != nil {
			return classifyStreamError(err)
		}
	}

	// Samples taken before this connection are sent as replayed; later ones live.
	var metricsReady <-chan struct{} // nil without metrics: that case never fires
	sendMetrics := func() error { return nil }
	if c.Metrics != nil {
		metricsReady = c.Metrics.Notify()
		cut := c.Now()
		sendMetrics = func() error {
			for {
				batch, commit := c.Metrics.Next(cut)
				if batch == nil {
					return nil
				}
				if err := stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Metrics{Metrics: batch}}); err != nil {
					return err
				}
				commit()
			}
		}
		if err := sendMetrics(); err != nil {
			return classifyStreamError(err)
		}
	}

	var logOut <-chan *agentv1.AgentMessage // nil without logs: that case never fires
	if c.Logs != nil {
		logOut = c.Logs.Out()
		defer c.Logs.CloseAll()
	}

	var checkOut <-chan *agentv1.AgentMessage // nil without checks: that case never fires
	if c.Checks != nil {
		checkOut = c.Checks.Out()
		defer c.Checks.CloseAll()
	}

	beat := time.NewTicker(interval)
	defer beat.Stop()
	renewTimer := time.NewTimer(time.Until(c.renewAt(id)))
	defer renewTimer.Stop()
	var pending *ecdsa.PrivateKey // key of an outstanding renewal request

	for {
		select {
		case <-beat.C:
			if err := stream.Send(heartbeat(c.Now(), c.Inventory, c.Metrics)); err != nil {
				return classifyStreamError(err)
			}
		case <-renewTimer.C:
			if pending != nil { // the previous request went unanswered; ask again
				pending = nil
			}
			key, csr, err := newKeyAndCSR()
			if err != nil {
				return err
			}
			if err := stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Renew{Renew: &agentv1.RenewRequest{CsrDer: csr}}}); err != nil {
				return classifyStreamError(err)
			}
			pending = key
			renewTimer.Reset(renewRetry)
		case m := <-in:
			switch body := m.GetBody().(type) {
			case *agentv1.ServerMessage_Renew:
				if pending == nil {
					continue
				}
				if err := identity.SaveCertificate(c.StateDir, body.Renew.GetCertDer(), pending); err != nil {
					return err
				}
				pending = nil
				renewTimer.Stop()
				c.Log.Info("certificate renewed; the new one is used from the next connection")
				// Reloading gives the next renewal time; the stream itself keeps running.
				if next, err := identity.Load(c.StateDir); err == nil {
					renewTimer.Reset(max(time.Until(c.renewAt(next)), time.Minute))
				}
			case *agentv1.ServerMessage_Disconnect:
				return classifyServerMessage(m, errors.New("the server closed the stream"))
			case *agentv1.ServerMessage_Config:
				if c.Metrics != nil {
					c.Metrics.SetInterval(body.Config.GetMetricIntervalSeconds())
				}
			case *agentv1.ServerMessage_OpenLog:
				if c.Logs != nil {
					c.Logs.Open(ctx, body.OpenLog)
				}
			case *agentv1.ServerMessage_CloseLog:
				if c.Logs != nil {
					c.Logs.Close(body.CloseLog.GetStreamId())
				}
			case *agentv1.ServerMessage_RunCheck:
				if c.Checks != nil {
					c.Checks.Run(ctx, body.RunCheck)
				}
			}
		case m := <-checkOut:
			if err := stream.Send(m); err != nil {
				return classifyStreamError(err)
			}
		case m := <-logOut:
			if err := stream.Send(m); err != nil {
				return classifyStreamError(err)
			}
		case <-metricsReady:
			if err := sendMetrics(); err != nil {
				return classifyStreamError(err)
			}
		case ev, ok := <-changes:
			var err error
			if ok {
				err = stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Event{Event: ev}})
			} else {
				err = attach() // fell behind: a fresh snapshot replaces the lost changes
			}
			if err != nil {
				return classifyStreamError(err)
			}
		case err := <-recvErr:
			return classifyStreamError(err)
		case <-ctx.Done():
			return nil
		}
	}
}

func hello(version string) *agentv1.AgentMessage {
	host, _ := os.Hostname()
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: protocolVersion, AgentVersion: version, Hostname: host, Os: runtime.GOOS, Arch: runtime.GOARCH,
	}}}
}

func heartbeat(now time.Time, inv Inventory, m Metrics) *agentv1.AgentMessage {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	stats := &agentv1.AgentStats{MemoryBytes: ms.Sys}
	if inv != nil {
		stats.CollectorErrors = inv.Errors()
	}
	if m != nil {
		stats.CollectorErrors = append(stats.CollectorErrors, m.Errors()...)
	}
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{SentAtUnixMs: now.UnixMilli(), Stats: stats}}}
}

func newKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	return key, csr, nil
}

// classifyServerMessage turns a Disconnect into errRevoked when it says so.
func classifyServerMessage(m *agentv1.ServerMessage, fallback error) error {
	if d := m.GetDisconnect(); d != nil {
		if d.GetReason() == agentv1.Disconnect_REASON_REVOKED {
			return errRevoked
		}
		return fmt.Errorf("%w (reason %s, code %q)", fallback, d.GetReason(), d.GetCode())
	}
	return fallback
}

// classifyStreamError maps a closed stream to errRevoked when the server said so, and
// otherwise returns it for a retry.
func classifyStreamError(err error) error {
	if errors.Is(err, io.EOF) {
		return errors.New("the server closed the stream")
	}
	if st, ok := status.FromError(err); ok && (st.Code() == codes.PermissionDenied || st.Message() == string(errcode.GWAuth001)) {
		return errRevoked
	}
	return err
}
