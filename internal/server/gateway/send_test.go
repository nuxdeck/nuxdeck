// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"
	"testing"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

func TestSendToAgent(t *testing.T) {
	g := &Gateway{reg: newRegistry()}
	msg := &agentv1.ServerMessage{}
	if err := g.SendToAgent("a1", msg); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("unknown agent: %v", err)
	}
	s := newSession("a1")
	g.reg.add(s)
	for range cap(s.outbox) {
		if err := g.SendToAgent("a1", msg); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.SendToAgent("a1", msg); !errors.Is(err, ErrAgentBusy) {
		t.Fatalf("full queue must not block: %v", err)
	}
	s.close(reasonRevoked)
	if err := g.SendToAgent("a1", msg); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("closing session: %v", err)
	}
}
