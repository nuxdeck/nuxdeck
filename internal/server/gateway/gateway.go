// SPDX-License-Identifier: AGPL-3.0-only

// Package gateway terminates agent connections on port 8444. Enrolment runs
// over plain TLS; everything else runs on one long-lived gRPC stream per agent
// authenticated by that agent's client certificate. The server only listens:
// agents dial out (AGT-2).
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Protocol and liveness constants (docs/03-architecture.md, "Agent connection lifecycle").
const (
	ProtocolVersion = 1
	// DefaultHeartbeat is how often agents send a heartbeat; three missed ones mean offline,
	// so a silent agent is flagged after 30 s, inside the 60 s of AGT-7.
	DefaultHeartbeat = 10 * time.Second
	// MissedHeartbeats is how many intervals may pass without a heartbeat.
	MissedHeartbeats = 3
	// MetricInterval is the collection interval told to agents (MET-4 default).
	MetricInterval = 15 * time.Second

	helloTimeout    = 10 * time.Second
	maxMessageBytes = 4 << 20
	touchInterval   = time.Minute
	stopTimeout     = 5 * time.Second

	enrolFailureLimit  = 10
	enrolFailureWindow = 5 * time.Minute
	maxTokenBytes      = 1024
	maxCSRBytes        = 8 << 10
)

// ErrAgentNotFound is returned by a Repository for an unknown agent ID.
var ErrAgentNotFound = errors.New("agent not found")

// AgentInfo is what the gateway needs to know about an enrolled agent.
type AgentInfo struct {
	ID         string
	CertSerial string
	Revoked    bool
}

// Repository is the persistence the gateway needs.
type Repository interface {
	AgentByID(ctx context.Context, id string) (AgentInfo, error)
	// RevokedSerials lists the certificate serials of every revoked agent, for the deny list.
	RevokedSerials(ctx context.Context) ([]string, error)
	// RevokeAgent sets revoked_at and appends ev in one transaction, returning every certificate
	// serial the agent was issued. changed is false when the
	// agent was already revoked, in which case nothing is written.
	RevokeAgent(ctx context.Context, id string, at time.Time, ev audit.Event) (serials []string, changed bool, err error)
	TouchAgent(ctx context.Context, id string, at time.Time) error
}

// Enroller redeems an enrolment token; *pki.Service implements it.
type Enroller interface {
	Enroll(ctx context.Context, req pki.EnrollRequest) (*pki.Enrollment, error)
}

// Renewer signs replacement certificates; *pki.Service implements it.
type Renewer interface {
	Renew(ctx context.Context, req pki.RenewRequest) (*pki.Renewal, error)
}

// Options are the gateway's dependencies.
type Options struct {
	Log      *slog.Logger
	Repo     Repository
	Enroller Enroller
	Renewer  Renewer
	CA       *pki.CA
	// ServerCert supplies the gateway's TLS certificate, normally pki.ServerCerts.GetCertificate.
	ServerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Heartbeat overrides DefaultHeartbeat; tests shorten it.
	Heartbeat time.Duration
	// OnMessage receives every message an agent sends after Hello (inventory, metrics, ...), in order,
	// on the stream's goroutine. It must not block.
	OnMessage func(agentID string, m *agentv1.AgentMessage)
	// OnPresence is told when an agent goes online or offline. It must not block.
	OnPresence func(agentID string, online bool)
	// Now supplies the clock; nil means time.Now.
	Now func() time.Time
}

// Gateway serves the AgentGateway gRPC service.
type Gateway struct {
	agentv1.UnimplementedAgentGatewayServer

	o       Options
	log     *slog.Logger
	grpc    *grpc.Server
	reg     *registry
	deny    *denyList
	limiter *auth.Limiter
}

// New builds the gateway and loads the revocation deny list from the database.
func New(ctx context.Context, o Options) (*Gateway, error) {
	if o.Heartbeat <= 0 {
		o.Heartbeat = DefaultHeartbeat
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	g := &Gateway{o: o, log: o.Log, reg: newRegistry(), deny: newDenyList(), limiter: auth.NewLimiter(enrolFailureLimit, enrolFailureWindow, o.Now)}

	serials, err := o.Repo.RevokedSerials(ctx)
	if err != nil {
		return nil, fmt.Errorf("load revoked certificates: %w", err)
	}
	g.deny.add(serials...)

	tlsConf := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: o.ServerCert,
		// Enroll comes without a certificate; Connect insists on one in its handler.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  o.CA.Pool(),
		// VerifyConnection, unlike VerifyPeerCertificate, also runs on resumed sessions; tickets are
		// off as well because agents hold one long stream and gain nothing from resuming.
		VerifyConnection:       g.verifyConnection,
		SessionTicketsDisabled: true,
	}
	g.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConf)),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 20 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
	)
	agentv1.RegisterAgentGatewayServer(g.grpc, g)
	return g, nil
}

// Listen binds the gateway address.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVIO003, "listen on "+addr, err)
	}
	return ln, nil
}

// Serve accepts agents on ln until ctx ends, then tells every agent the server is
// shutting down and drains.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- g.grpc.Serve(ln) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	g.reg.closeAll(reasonShuttingDown)
	done := make(chan struct{})
	go func() { g.grpc.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopTimeout):
		g.grpc.Stop()
	}
	return nil
}

// verifyConnection runs on every handshake, after the chain was verified against the
// agent CA, and refuses revoked certificates before any RPC is attempted.
func (g *Gateway) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 {
		return nil
	}
	if g.deny.has(cs.VerifiedChains[0][0].SerialNumber.Text(16)) {
		return errors.New("agent certificate revoked")
	}
	return nil
}

// Online reports whether the agent currently has a live stream.
func (g *Gateway) Online(agentID string) bool { return g.reg.get(agentID) != nil }

func (g *Gateway) presence(agentID string, online bool) {
	if g.o.OnPresence != nil {
		g.o.OnPresence(agentID, online)
	}
}

type denyList struct {
	mu      sync.RWMutex
	serials map[string]struct{}
}

func newDenyList() *denyList { return &denyList{serials: map[string]struct{}{}} }

func (d *denyList) add(serials ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range serials {
		d.serials[s] = struct{}{}
	}
}

func (d *denyList) has(serial string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.serials[serial]
	return ok
}
