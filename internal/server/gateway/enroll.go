// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Enroll trades a single-use token and a CSR for the agent's first certificate.
// Failures count against the caller's address so the unauthenticated endpoint
// can neither guess tokens nor flood the audit log.
func (g *Gateway) Enroll(ctx context.Context, in *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	ip := peerIP(ctx)
	if g.limiter.Blocked(ip) {
		return nil, status.Error(codes.ResourceExhausted, string(errcode.GWRate001))
	}
	if len(in.GetToken()) > maxTokenBytes || len(in.GetCsrDer()) > maxCSRBytes {
		g.limiter.Fail(ip)
		return nil, status.Error(codes.InvalidArgument, string(errcode.GWCSR001))
	}

	res, err := g.o.Enroller.Enroll(ctx, pki.EnrollRequest{
		Token: in.GetToken(), CSRDER: in.GetCsrDer(), Version: in.GetAgentVersion(),
		Hostname: in.GetHostname(), OS: in.GetOs(), Arch: in.GetArch(), IP: ip,
	})
	switch errcode.CodeOf(err) {
	case "":
		if err != nil {
			g.log.Error("enrolment failed", "ip", ip, "error", err)
			return nil, status.Error(codes.Internal, string(errcode.APIInt001))
		}
	case errcode.GWTok001:
		g.limiter.Fail(ip)
		return nil, status.Error(codes.Unauthenticated, string(errcode.GWTok001))
	case errcode.GWCSR001:
		g.limiter.Fail(ip)
		return nil, status.Error(codes.InvalidArgument, string(errcode.GWCSR001))
	default:
		g.log.Error("enrolment failed", "ip", ip, "error", err)
		return nil, status.Error(codes.Internal, string(errcode.APIInt001))
	}

	g.log.Info("agent enrolled", "agent_id", res.AgentID, "ip", ip)
	return &agentv1.EnrollResponse{
		AgentId: res.AgentID, CertDer: res.CertDER, CaCertDer: res.CACertDER, RenewAfterUnix: res.RenewAfter.Unix(),
	}, nil
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
		return host
	}
	return p.Addr.String()
}
