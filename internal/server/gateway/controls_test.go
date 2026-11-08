// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// frozenClock keeps the token buckets from refilling, so drop counts are exact.
func frozenClock(o *gateway.Options) {
	at := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	o.Now = func() time.Time { return at }
}

// connectFrom dials the gateway from a chosen local address, so the server sees another peer IP.
func (e *env) connectFrom(a agent, localIP string) *conn {
	e.t.Helper()
	local := &net.TCPAddr{IP: net.ParseIP(localIP)}
	cc, err := grpc.NewClient(e.addr,
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{LocalAddr: local}
			return d.DialContext(ctx, "tcp", addr)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: e.ca.Pool(), ServerName: "localhost", Certificates: []tls.Certificate{a.cert}, MinVersion: tls.VersionTLS13,
		})))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = cc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayClient(cc).Connect(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	return &conn{stream: stream, cancel: cancel}
}

// upFrom is up, from a chosen local address.
func (e *env) upFrom(a agent, localIP string) *conn {
	e.t.Helper()
	c := e.connectFrom(a, localIP)
	if err := c.stream.Send(hello()); err != nil {
		e.t.Fatal(err)
	}
	if m := c.recv(e.t, 5*time.Second); m.GetHelloAck() == nil {
		e.t.Fatalf("first server message = %v, want HelloAck", m)
	}
	return c
}

func (e *env) auditCount(t *testing.T, action string) int {
	t.Helper()
	entries, _, err := e.db.SearchAudit(context.Background(), store.AuditFilter{ActionPrefix: action}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestT13_FloodingAgentIsDroppedThenClosedWithStableCode(t *testing.T) {
	e := newEnvTuned(t, nil, func(o *gateway.Options) {
		frozenClock(o)
		o.MessageBurst = 5
		o.MessageRate = 1
		o.MaxDroppedMsgs = 10
	})
	a := e.enroll()
	c := e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)

	// Five admitted and ten dropped: the tenth drop closes the stream.
	for range 40 {
		if err := c.stream.Send(heartbeat()); err != nil {
			break
		}
	}
	m := c.recv(t, 5*time.Second)
	if d := m.GetDisconnect(); d == nil || d.Code != string(errcode.GWStr005) {
		t.Fatalf("got %v, want a Disconnect with %s", m, errcode.GWStr005)
	}
	e.wantPresence(a.id, false, 2*time.Second)
	if n := e.auditCount(t, "agent.stream.flooded"); n != 1 {
		t.Errorf("flood audit entries = %d, want 1", n)
	}
}

func TestT13_FloodFromOneAgentDoesNotStallAnother(t *testing.T) {
	e := newEnvTuned(t, nil, func(o *gateway.Options) {
		frozenClock(o)
		o.MessageBurst = 5
		o.MessageRate = 1
		o.MaxDroppedMsgs = 1 << 30
	})
	flooder := e.enroll()
	quiet := e.enroll()
	f := e.up(flooder)
	q := e.up(quiet)
	e.wantPresence(flooder.id, true, 2*time.Second)
	e.wantPresence(quiet.id, true, 2*time.Second)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 5000 {
			if err := f.stream.Send(heartbeat()); err != nil {
				return
			}
		}
	}()

	if err := e.gw.SendToAgent(quiet.id, &agentv1.ServerMessage{}); err != nil {
		t.Fatal(err)
	}
	if m, err := q.recvErr(2 * time.Second); err != nil || m == nil {
		t.Fatalf("quiet agent's message was not delivered during the flood: %v", err)
	}
	<-done
	if !e.gw.Online(quiet.id) {
		t.Error("the quiet agent went offline while another agent flooded")
	}
}

func TestT3_ReconnectFromSameAddressRaisesNoConflict(t *testing.T) {
	conflicts := make(chan gateway.IdentityConflict, 4)
	e := newEnvTuned(t, nil, func(o *gateway.Options) {
		o.OnIdentityConflict = func(c gateway.IdentityConflict) { conflicts <- c }
	})
	a := e.enroll()
	e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)
	e.upFrom(a, "127.0.0.1")

	select {
	case c := <-conflicts:
		t.Fatalf("same-address reconnect reported a conflict: %+v", c)
	case <-time.After(200 * time.Millisecond):
	}
	if n := e.auditCount(t, "agent.identity.dual_address"); n != 0 {
		t.Errorf("dual-address audit entries = %d, want 0", n)
	}
}

func TestT3_ReconnectFromAnotherAddressRaisesConflict(t *testing.T) {
	conflicts := make(chan gateway.IdentityConflict, 4)
	e := newEnvTuned(t, nil, func(o *gateway.Options) {
		o.OnIdentityConflict = func(c gateway.IdentityConflict) { conflicts <- c }
	})
	a := e.enroll()
	old := e.up(a)
	e.wantPresence(a.id, true, 2*time.Second)

	fresh := e.upFrom(a, "127.0.0.2")
	m := old.recv(t, 5*time.Second)
	if d := m.GetDisconnect(); d == nil || d.Code != string(errcode.GWStr003) {
		t.Fatalf("old stream got %v, want a replaced Disconnect", m)
	}

	select {
	case c := <-conflicts:
		if c.AgentID != a.id || c.PreviousIP != "127.0.0.1" || c.CurrentIP != "127.0.0.2" {
			t.Errorf("conflict = %+v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no OnIdentityConflict call for a reconnect from another address")
	}
	if n := e.auditCount(t, "agent.identity.dual_address"); n != 1 {
		t.Fatalf("dual-address audit entries = %d, want 1", n)
	}
	entries, _, err := e.db.SearchAudit(context.Background(), store.AuditFilter{ActionPrefix: "agent.identity.dual_address"}, 0, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("search audit: %v, %d entries", err, len(entries))
	}
	ev := entries[0].Event
	if ev.TargetID != a.id || ev.IP != "127.0.0.2" || entries[0].DetailsJSON != `{"current_ip":"127.0.0.2","previous_ip":"127.0.0.1"}` {
		t.Errorf("audit entry = %+v details %s", ev, entries[0].DetailsJSON)
	}
	if !e.gw.Online(a.id) {
		t.Error("the agent went offline although its new stream is live")
	}
	if err := fresh.stream.Send(heartbeat()); err != nil {
		t.Errorf("new stream broke: %v", err)
	}
}

// A revocation that lands between authentication and registration must still end the stream.
func TestAGT4_RevocationBeforeRegistrationEndsTheStream(t *testing.T) {
	e := newEnv(t)
	a := e.enroll()
	c := e.connect(a)
	time.Sleep(100 * time.Millisecond) // let the handler authenticate while it waits for Hello
	if err := e.gw.Revoke(context.Background(), gateway.Actor{UserID: "01ADMIN"}, a.id); err != nil {
		t.Fatal(err)
	}
	if err := c.stream.Send(hello()); err != nil {
		t.Fatal(err)
	}
	if m, err := c.recvErr(5 * time.Second); err == nil && m.GetHelloAck() != nil {
		t.Fatal("a revoked agent received a HelloAck")
	}
	if e.gw.Online(a.id) {
		t.Error("a revoked agent is registered as online")
	}
	for {
		select {
		case ev := <-e.events:
			if ev.agent == a.id && ev.online {
				t.Fatal("a revoked agent was reported online")
			}
		default:
			return
		}
	}
}
