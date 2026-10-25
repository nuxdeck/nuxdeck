// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const beat = 100 * time.Millisecond

type presence struct {
	agent  string
	online bool
}

type env struct {
	t        *testing.T
	dir      string
	db       *store.Store
	ca       *pki.CA
	pki      *pki.Service
	gw       *gateway.Gateway
	addr     string
	events   chan presence
	msgs     chan *agentv1.AgentMessage
	stopGW   context.CancelFunc
	gwStoped chan struct{}
}

func newEnv(t *testing.T) *env { return newEnvWith(t, nil) }

// newEnvWith lets a test wrap the repository the gateway sees.
func newEnvWith(t *testing.T, wrap func(gateway.Repository) gateway.Repository) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateAdmin(context.Background(),
		auth.User{ID: "01ADMIN", Email: "ada@example.com", Name: "Ada", PasswordHash: "x", CreatedAt: time.Now()},
		audit.Event{ActorType: "user", ActorID: "01ADMIN", Action: "setup.complete", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, db: db, ca: ca, pki: pki.NewService(db, ca), events: make(chan presence, 64), msgs: make(chan *agentv1.AgentMessage, 1024), gwStoped: make(chan struct{})}

	var repo gateway.Repository = db
	if wrap != nil {
		repo = wrap(db)
	}
	e.gw, err = gateway.New(context.Background(), gateway.Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Repo: repo, Enroller: e.pki, Renewer: e.pki, CA: ca,
		ServerCert: ca.ServerCertificates([]string{"localhost", "127.0.0.1"}).GetCertificate,
		Heartbeat:  beat,
		OnPresence: func(id string, online bool) { e.events <- presence{id, online} },
		OnMessage: func(_ string, m *agentv1.AgentMessage) {
			select {
			case e.msgs <- m:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gateway.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	e.stopGW = cancel
	go func() { defer close(e.gwStoped); _ = e.gw.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-e.gwStoped })
	return e
}

type agent struct {
	id   string
	cert tls.Certificate
}

func (e *env) dial(roots *x509.CertPool, certs ...tls.Certificate) *grpc.ClientConn {
	e.t.Helper()
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: roots, ServerName: "localhost", Certificates: certs, MinVersion: tls.VersionTLS13,
	})))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func (e *env) token() string {
	e.t.Helper()
	c, err := e.pki.CreateToken(context.Background(), pki.Actor{UserID: "01ADMIN"}, pki.TokenRequest{ServerURL: "https://" + e.addr})
	if err != nil {
		e.t.Fatal(err)
	}
	return c.Token
}

func (e *env) enroll() agent {
	e.t.Helper()
	key, csr := newCSR(e.t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool())).Enroll(ctx, &agentv1.EnrollRequest{
		Token: e.token(), CsrDer: csr, AgentVersion: "0.1.0", Hostname: "web-1", Os: "linux", Arch: "amd64",
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return agent{id: res.AgentId, cert: tls.Certificate{Certificate: [][]byte{res.CertDer}, PrivateKey: key}}
}

type conn struct {
	stream agentv1.AgentGateway_ConnectClient
	cancel context.CancelFunc
}

func (e *env) connect(a agent) *conn {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool(), a.cert)).Connect(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	return &conn{stream: stream, cancel: cancel}
}

func hello() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{ProtocolVersion: 1, AgentVersion: "0.1.0"}}}
}

func heartbeat() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}
}

// up connects, says Hello and waits for the ack.
func (e *env) up(a agent) *conn {
	e.t.Helper()
	c := e.connect(a)
	if err := c.stream.Send(hello()); err != nil {
		e.t.Fatal(err)
	}
	m := c.recv(e.t, 5*time.Second)
	if m.GetHelloAck() == nil {
		e.t.Fatalf("first server message = %v, want HelloAck", m)
	}
	return c
}

// recv returns the next server message, or fails the test.
func (c *conn) recv(t *testing.T, within time.Duration) *agentv1.ServerMessage {
	t.Helper()
	m, err := c.recvErr(within)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return m
}

func (c *conn) recvErr(within time.Duration) (*agentv1.ServerMessage, error) {
	type result struct {
		m   *agentv1.ServerMessage
		err error
	}
	ch := make(chan result, 1)
	go func() { m, err := c.stream.Recv(); ch <- result{m, err} }()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-time.After(within):
		return nil, context.DeadlineExceeded
	}
}

func (e *env) wantPresence(id string, online bool, within time.Duration) time.Duration {
	e.t.Helper()
	start := time.Now()
	deadline := time.After(within)
	for {
		select {
		case ev := <-e.events:
			if ev.agent == id && ev.online == online {
				return time.Since(start)
			}
		case <-deadline:
			e.t.Fatalf("agent %s did not go online=%v within %v", id, online, within)
		}
	}
}

func wantStatus(t *testing.T, err error, c codes.Code, code errcode.Code) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok || st.Code() != c || st.Message() != string(code) {
		t.Fatalf("error = %v, want %s %s", err, c, code)
	}
}

func TestAGT3_AgentVerifiesTheGatewayAgainstTheCA(t *testing.T) {
	e := newEnv(t)
	_, csr := newCSR(t)

	other, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = agentv1.NewAgentGatewayClient(e.dial(other.Pool())).Enroll(ctx, &agentv1.EnrollRequest{Token: e.token(), CsrDer: csr})
	if err == nil {
		t.Fatal("an agent trusting a different CA must not talk to this gateway")
	}

	e.enroll() // the right CA works, and spent a token the failed attempt never reached
}

func TestEnrollRPCIssuesAWorkingIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.enroll()
	leaf, err := x509.ParseCertificate(a.cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := pki.AgentIDFromCert(leaf); !ok || id != a.id {
		t.Errorf("certificate names %q, response says %q", id, a.id)
	}
	if _, err := e.db.AgentByID(context.Background(), a.id); err != nil {
		t.Errorf("agent row: %v", err)
	}
}

func TestEnrollFailuresAreRateLimitedPerAddress(t *testing.T) {
	e := newEnv(t)
	_, csr := newCSR(t)
	client := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool()))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	bad, _ := pki.NewToken("https://nux.example.com:8444", e.ca.Fingerprint())
	for range 10 {
		_, err := client.Enroll(ctx, &agentv1.EnrollRequest{Token: bad.String(), CsrDer: csr})
		wantStatus(t, err, codes.Unauthenticated, errcode.GWTok001)
	}
	valid := e.token() // creating it is audited, so do it before counting
	before, _ := e.db.VerifyAuditChain(ctx)

	_, err := client.Enroll(ctx, &agentv1.EnrollRequest{Token: valid, CsrDer: csr})
	wantStatus(t, err, codes.ResourceExhausted, errcode.GWRate001)
	if after, _ := e.db.VerifyAuditChain(ctx); after != before {
		t.Errorf("a blocked caller still reached the audit log (%d -> %d entries)", before, after)
	}
}

func TestConnectNeedsAnEnrolledAgentCertificate(t *testing.T) {
	e := newEnv(t)
	good := e.enroll()

	t.Run("no certificate", func(t *testing.T) {
		stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool())).Connect(context.Background())
		if err == nil {
			_, err = stream.Recv()
		}
		wantStatus(t, err, codes.Unauthenticated, errcode.GWAuth001)
	})

	t.Run("certificate from another CA", func(t *testing.T) {
		other, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "pki"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		key, csr := newCSR(t)
		issued, err := other.Sign(csr, good.id, time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		forged := agent{id: good.id, cert: tls.Certificate{Certificate: [][]byte{issued.DER}, PrivateKey: key}}
		stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool(), forged.cert)).Connect(context.Background())
		if err == nil {
			_, err = stream.Recv()
		}
		if err == nil {
			t.Fatal("a certificate signed by another CA was accepted")
		}
	})

	t.Run("valid CA but never enrolled", func(t *testing.T) {
		key, csr := newCSR(t)
		issued, err := e.ca.Sign(csr, "01HZZZZZZZZZZZZZZZZZZZZZZZ", time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cert := tls.Certificate{Certificate: [][]byte{issued.DER}, PrivateKey: key}
		stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool(), cert)).Connect(context.Background())
		if err == nil {
			_, err = stream.Recv()
		}
		wantStatus(t, err, codes.Unauthenticated, errcode.GWAuth001)
	})
}

func TestStreamMustStartWithHello(t *testing.T) {
	e := newEnv(t)
	c := e.connect(e.enroll())
	if err := c.stream.Send(heartbeat()); err != nil {
		t.Fatal(err)
	}
	m := c.recv(t, 5*time.Second)
	if d := m.GetDisconnect(); d == nil || d.Reason != agentv1.Disconnect_REASON_PROTOCOL_ERROR || d.Code != string(errcode.GWStr001) {
		t.Fatalf("got %v, want a protocol-error Disconnect", m)
	}
}

func TestAGT7_SilentAgentGoesOfflineAfterThreeMissedHeartbeats(t *testing.T) {
	if gateway.MissedHeartbeats*gateway.DefaultHeartbeat > 60*time.Second {
		t.Fatalf("defaults give %v to detect a dead agent; AGT-7 allows 60s", gateway.MissedHeartbeats*gateway.DefaultHeartbeat)
	}

	e := newEnv(t)
	a := e.enroll()
	e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)
	if !e.gw.Online(a.id) {
		t.Error("Online = false for a connected agent")
	}

	took := e.wantPresence(a.id, false, gateway.MissedHeartbeats*beat+2*time.Second)
	if took < (gateway.MissedHeartbeats-1)*beat {
		t.Errorf("marked offline after %v, before three heartbeats were missed", took)
	}
	if e.gw.Online(a.id) {
		t.Error("Online = true after the agent went silent")
	}
}

func TestAGT7_HeartbeatsKeepAnAgentOnline(t *testing.T) {
	e := newEnv(t)
	a := e.enroll()
	c := e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)

	for range 12 { // 12 × 50 ms is twice the 300 ms window
		if err := c.stream.Send(heartbeat()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(beat / 2)
	}
	select {
	case ev := <-e.events:
		t.Fatalf("unexpected presence change %+v while heartbeats flow", ev)
	default:
	}
}

func TestAGT7_ClosedConnectionGoesOfflineImmediately(t *testing.T) {
	e := newEnv(t)
	a := e.enroll()
	c := e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)

	c.cancel()
	if took := e.wantPresence(a.id, false, 2*time.Second); took >= gateway.MissedHeartbeats*beat {
		t.Errorf("a closed stream took %v to show offline", took)
	}
}

func TestAGT4_RevocationDisconnectsAndBlocksReconnect(t *testing.T) {
	e := newEnv(t)
	a := e.enroll()
	c := e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)
	base, _ := e.db.VerifyAuditChain(context.Background())

	start := time.Now()
	if err := e.gw.Revoke(context.Background(), gateway.Actor{UserID: "01ADMIN", IP: "198.51.100.7"}, a.id); err != nil {
		t.Fatal(err)
	}
	m := c.recv(t, 5*time.Second)
	if d := m.GetDisconnect(); d == nil || d.Reason != agentv1.Disconnect_REASON_REVOKED {
		t.Fatalf("got %v, want a Disconnect with REASON_REVOKED", m)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Errorf("disconnect took %v, AGT-4 allows 30s", took)
	}
	e.wantPresence(a.id, false, 2*time.Second)

	// Reconnecting with the same certificate fails at the handshake.
	stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool(), a.cert)).Connect(context.Background())
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("a revoked certificate was accepted")
	}

	if err := e.gw.Revoke(context.Background(), gateway.Actor{UserID: "01ADMIN"}, a.id); err != nil {
		t.Errorf("revoking twice: %v", err)
	}
	if n, err := e.db.VerifyAuditChain(context.Background()); err != nil || n != base+1 {
		t.Errorf("audit chain has %d entries (want %d, exactly one revoke), %v", n, base+1, err)
	}
}

func TestRevokeUnknownAgent(t *testing.T) {
	e := newEnv(t)
	err := e.gw.Revoke(context.Background(), gateway.Actor{UserID: "01ADMIN"}, "01HZZZZZZZZZZZZZZZZZZZZZZZ")
	if err == nil || err.Error() != gateway.ErrAgentNotFound.Error() {
		t.Errorf("err = %v, want ErrAgentNotFound", err)
	}
}

// hidesRevocation makes the database claim nobody is revoked, so only the deny list can stop a connection.
type hidesRevocation struct{ gateway.Repository }

func (h hidesRevocation) AgentByID(ctx context.Context, id string) (gateway.AgentInfo, error) {
	info, err := h.Repository.AgentByID(ctx, id)
	info.Revoked = false
	return info, err
}

func TestAGT4_DenyListSurvivesRestart(t *testing.T) {
	var first *env
	e := newEnvWith(t, func(r gateway.Repository) gateway.Repository { return hidesRevocation{r} })
	first = e
	a := e.enroll()
	if err := first.db.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.gw.Revoke(context.Background(), gateway.Actor{UserID: "01ADMIN"}, a.id); err != nil {
		t.Fatal(err)
	}

	// A gateway built afterwards must load the deny list from the database.
	restarted, err := gateway.New(context.Background(), gateway.Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Repo: hidesRevocation{e.db}, Enroller: e.pki, Renewer: e.pki, CA: e.ca,
		ServerCert: e.ca.ServerCertificates([]string{"localhost", "127.0.0.1"}).GetCertificate, Heartbeat: beat,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gateway.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = restarted.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); wg.Wait() })

	e.addr = ln.Addr().String()
	stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool(), a.cert)).Connect(context.Background())
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("the restarted gateway accepted a revoked certificate")
	}
}

func TestNewConnectionReplacesTheOldOneWithoutGoingOffline(t *testing.T) {
	e := newEnv(t)
	a := e.enroll()
	old := e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)

	fresh := e.up(a)
	m := old.recv(t, 5*time.Second)
	if d := m.GetDisconnect(); d == nil || d.Code != string(errcode.GWStr003) {
		t.Fatalf("old stream got %v, want a replaced Disconnect", m)
	}
	if !e.gw.Online(a.id) {
		t.Error("the agent went offline although its new stream is live")
	}
	if err := fresh.stream.Send(heartbeat()); err != nil {
		t.Errorf("new stream broke: %v", err)
	}
}

func TestShutdownTellsAgentsGoodbye(t *testing.T) {
	e := newEnv(t)
	c := e.up(e.enroll())

	e.stopGW()
	m := c.recv(t, 5*time.Second)
	if d := m.GetDisconnect(); d == nil || d.Reason != agentv1.Disconnect_REASON_SHUTTING_DOWN {
		t.Fatalf("got %v, want a SHUTTING_DOWN Disconnect", m)
	}
	select {
	case <-e.gwStoped:
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not stop")
	}
}

func TestServerCertificateIsReusedAndRenewed(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	src := ca.ServerCertificates([]string{"nux.example.com", "10.0.0.5"})
	src.Now = func() time.Time { return now }

	a, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := src.GetCertificate(nil); b != a {
		t.Error("a fresh certificate must be reused")
	}
	leaf, _ := x509.ParseCertificate(a.Certificate[0])
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "nux.example.com" || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("SANs = %v %v", leaf.DNSNames, leaf.IPAddresses)
	}

	now = now.Add(70 * 24 * time.Hour) // under 30 days left
	if c, _ := src.GetCertificate(nil); c == a {
		t.Error("a certificate close to expiry must be replaced")
	}
}
