// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"errors"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Actor identifies who asked for a state change, for the audit entry.
type Actor struct {
	UserID string
	IP     string
}

// Revoke ends an agent's access: its certificate serial joins the deny list, so the
// handshake refuses it from now on, and any live stream is closed at once (AGT-4).
// Revoking twice is harmless.
func (g *Gateway) Revoke(ctx context.Context, actor Actor, agentID string) error {
	serial, changed, err := g.o.Repo.RevokeAgent(ctx, agentID, g.o.Now(), audit.Event{
		ActorType: "user", ActorID: actor.UserID, Action: "agent.revoke",
		TargetType: "agent", TargetID: agentID, IP: actor.IP, Result: audit.ResultSuccess,
	})
	if err != nil {
		return err
	}
	g.deny.add(serial)
	if s := g.reg.get(agentID); s != nil {
		s.close(reasonRevoked)
	}
	if changed {
		g.log.Info("agent revoked", "agent_id", agentID, "by", actor.UserID)
	}
	return nil
}

// authenticate maps the verified client certificate to an enrolled, unrevoked agent.
// It fails closed: no certificate, an unknown agent or a denied serial all end here.
func (g *Gateway) authenticate(ctx context.Context) (string, error) {
	deny := func() (string, error) { return "", status.Error(codes.Unauthenticated, string(errcode.GWAuth001)) }

	p, ok := peer.FromContext(ctx)
	if !ok {
		return deny()
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 {
		return deny()
	}
	leaf := ti.State.VerifiedChains[0][0]
	id, ok := pki.AgentIDFromCert(leaf)
	if !ok || g.deny.has(leaf.SerialNumber.Text(16)) {
		return deny()
	}
	info, err := g.o.Repo.AgentByID(ctx, id)
	switch {
	case errors.Is(err, ErrAgentNotFound):
		return deny()
	case err != nil:
		g.log.Error("look up agent", "agent_id", id, "error", err)
		return "", status.Error(codes.Internal, string(errcode.APIInt001))
	case info.Revoked:
		return deny()
	}
	return id, nil
}

// Connect is the agent's long-lived stream. After Hello it expects a heartbeat at
// least every MissedHeartbeats intervals and treats silence as a disconnect.
func (g *Gateway) Connect(stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	ctx := stream.Context()
	agentID, err := g.authenticate(ctx)
	if err != nil {
		return err
	}

	msgs, recvErr := readMessages(stream)
	if err := g.expectHello(ctx, stream, msgs, recvErr); err != nil {
		return err
	}

	sess := newSession(agentID)
	if old := g.reg.add(sess); old != nil {
		old.close(reasonReplaced)
	}
	log := g.log.With("agent_id", agentID)
	log.Info("agent connected")
	g.presence(agentID, true)
	g.touch(ctx, agentID)
	defer func() {
		if g.reg.remove(sess) {
			g.presence(agentID, false)
			g.touch(context.WithoutCancel(ctx), agentID)
			log.Info("agent offline")
		}
	}()

	if err := stream.Send(&agentv1.ServerMessage{Body: &agentv1.ServerMessage_HelloAck{HelloAck: &agentv1.HelloAck{
		ProtocolVersion:          ProtocolVersion,
		HeartbeatIntervalSeconds: uint32(g.o.Heartbeat.Seconds()),
		MetricIntervalSeconds:    uint32(MetricInterval.Seconds()),
		MaxMessageBytes:          maxMessageBytes,
		ServerTimeUnixMs:         g.o.Now().UnixMilli(),
	}}}); err != nil {
		return err
	}

	window := MissedHeartbeats * g.o.Heartbeat
	timer := time.NewTimer(window)
	defer timer.Stop()
	lastTouch := g.o.Now()
	for {
		select {
		case m := <-msgs:
			switch m.GetBody().(type) {
			case *agentv1.AgentMessage_Heartbeat:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(window)
				if now := g.o.Now(); now.Sub(lastTouch) >= touchInterval {
					lastTouch = now
					g.touch(ctx, agentID)
				}
			case *agentv1.AgentMessage_Hello:
				return g.reject(stream, reasonProtocol)
			default:
				// Inventory, metrics and logs are consumed by modules that land later (NUX-16, 21, 24).
			}
		case m := <-sess.outbox:
			if err := stream.Send(m); err != nil {
				return err
			}
		case <-sess.closing:
			return g.reject(stream, sess.reason)
		case err := <-recvErr:
			return streamEnd(err)
		case <-timer.C:
			log.Warn("agent heartbeats missed", "after", window)
			return status.Error(codes.DeadlineExceeded, string(errcode.GWStr004))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// expectHello waits for the mandatory first message.
func (g *Gateway) expectHello(ctx context.Context, stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage],
	msgs <-chan *agentv1.AgentMessage, recvErr <-chan error,
) error {
	timer := time.NewTimer(helloTimeout)
	defer timer.Stop()
	select {
	case m := <-msgs:
		if h := m.GetHello(); h != nil && h.GetProtocolVersion() >= ProtocolVersion {
			return nil
		}
		return g.reject(stream, reasonProtocol)
	case err := <-recvErr:
		return streamEnd(err)
	case <-timer.C:
		return g.reject(stream, reasonProtocol)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// reject tells the agent why the stream ends, then ends it.
func (g *Gateway) reject(stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage], r closeReason) error {
	_ = stream.Send(&agentv1.ServerMessage{Body: &agentv1.ServerMessage_Disconnect{Disconnect: &agentv1.Disconnect{Reason: r.reason, Code: string(r.code)}}})
	switch r.reason {
	case agentv1.Disconnect_REASON_REVOKED:
		return status.Error(codes.PermissionDenied, string(r.code))
	case agentv1.Disconnect_REASON_PROTOCOL_ERROR:
		return status.Error(codes.InvalidArgument, string(r.code))
	default:
		return nil
	}
}

func (g *Gateway) touch(ctx context.Context, agentID string) {
	if err := g.o.Repo.TouchAgent(ctx, agentID, g.o.Now()); err != nil {
		g.log.Warn("record agent last seen", "agent_id", agentID, "error", err)
	}
}

// readMessages pumps Recv into a channel so the handler can select on it.
func readMessages(stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage]) (<-chan *agentv1.AgentMessage, <-chan error) {
	msgs := make(chan *agentv1.AgentMessage)
	errc := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			select {
			case msgs <- m:
			case <-stream.Context().Done():
				return
			}
		}
	}()
	return msgs, errc
}

func streamEnd(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
