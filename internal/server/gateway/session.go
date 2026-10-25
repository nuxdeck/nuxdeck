// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"sync"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// closeReason is why the server ends a stream, as told to the agent in Disconnect.
type closeReason struct {
	reason agentv1.Disconnect_Reason
	code   errcode.Code
}

var (
	reasonRevoked      = closeReason{agentv1.Disconnect_REASON_REVOKED, errcode.GWAuth001}
	reasonShuttingDown = closeReason{agentv1.Disconnect_REASON_SHUTTING_DOWN, ""}
	reasonReplaced     = closeReason{agentv1.Disconnect_REASON_UNSPECIFIED, errcode.GWStr003}
	reasonProtocol     = closeReason{agentv1.Disconnect_REASON_PROTOCOL_ERROR, errcode.GWStr001}
)

// session is one live agent stream. Only the Connect handler's goroutine sends on
// the gRPC stream; other goroutines ask it to by closing the session or queueing.
type session struct {
	agentID string

	once    sync.Once
	closing chan struct{}
	reason  closeReason // written before closing is closed
	outbox  chan *agentv1.ServerMessage
}

func newSession(agentID string) *session {
	return &session{agentID: agentID, closing: make(chan struct{}), outbox: make(chan *agentv1.ServerMessage, 16)}
}

// close asks the handler to send Disconnect and end the stream. Later calls are ignored.
func (s *session) close(r closeReason) {
	s.once.Do(func() {
		s.reason = r
		close(s.closing)
	})
}

// registry holds the live session per agent.
type registry struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newRegistry() *registry { return &registry{sessions: map[string]*session{}} }

// add makes s the agent's session and returns the one it replaced, if any.
func (r *registry) add(s *session) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.sessions[s.agentID]
	r.sessions[s.agentID] = s
	return old
}

// remove drops s and reports whether it was still the current session. A session
// that was replaced must not mark the agent offline.
func (r *registry) remove(s *session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[s.agentID] != s {
		return false
	}
	delete(r.sessions, s.agentID)
	return true
}

func (r *registry) get(agentID string) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[agentID]
}

func (r *registry) closeAll(reason closeReason) {
	r.mu.Lock()
	all := make([]*session, 0, len(r.sessions))
	for _, s := range r.sessions {
		all = append(all, s)
	}
	r.mu.Unlock()
	for _, s := range all {
		s.close(reason)
	}
}
