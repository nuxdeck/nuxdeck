// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Errors from SendToAgent.
var (
	ErrAgentOffline = errors.New("agent not connected")
	ErrAgentBusy    = errors.New("agent send queue full")
)

// SendToAgent queues m for the agent's live stream. It never blocks: a full queue is
// reported as ErrAgentBusy so callers can retry or drop.
func (g *Gateway) SendToAgent(agentID string, m *agentv1.ServerMessage) error {
	s := g.reg.get(agentID)
	if s == nil {
		return ErrAgentOffline
	}
	select {
	case <-s.closing:
		return ErrAgentOffline
	default:
	}
	select {
	case s.outbox <- m:
		return nil
	default:
		return ErrAgentBusy
	}
}
