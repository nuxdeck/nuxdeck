// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// actionIdentityDualAddress is the audit action for one agent identity seen from two addresses.
const actionIdentityDualAddress = "agent.identity.dual_address"

// actionStreamFlooded is the audit action for a stream closed by the per-agent message limit.
const actionStreamFlooded = "agent.stream.flooded"

// checkIdentityConflict runs when next replaces prev as the agent's stream. A different peer address
// while prev was still active is recorded in the audit log and reported to OnIdentityConflict.
// A reconnect from the same address is routine and produces nothing.
func (g *Gateway) checkIdentityConflict(ctx context.Context, prev, next *session) {
	now := g.o.Now()
	if prev.peerIP == "" || next.peerIP == "" || prev.peerIP == next.peerIP {
		return
	}
	if now.Sub(prev.lastSeenAt()) > identityConflictWindow {
		return
	}
	conflict := IdentityConflict{AgentID: next.agentID, PreviousIP: prev.peerIP, CurrentIP: next.peerIP, At: now}
	log := g.log.With("agent_id", next.agentID, "previous_ip", prev.peerIP, "current_ip", next.peerIP)
	log.Warn("agent identity connected from two addresses")

	ev := audit.Event{
		ActorType: "agent", ActorID: next.agentID, Action: actionIdentityDualAddress,
		TargetType: "agent", TargetID: next.agentID, IP: next.peerIP, Result: audit.ResultSuccess,
		Details: map[string]any{"previous_ip": prev.peerIP, "current_ip": next.peerIP},
	}
	// The stream is already replacing the old one; a failed audit write must not also refuse the agent.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := g.o.Repo.RecordAudit(auditCtx, ev); err != nil {
		log.Error("record identity conflict audit", "error", err)
	}
	if g.o.OnIdentityConflict != nil {
		g.o.OnIdentityConflict(conflict)
	}
}
