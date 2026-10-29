// SPDX-License-Identifier: AGPL-3.0-only

package checks

import "sync"

const subscriberBuffer = 64

// Hub fans state-change events out to in-process subscribers (the alert engine, the live
// stream) without ever blocking the publisher. A subscriber that falls behind is closed and
// must re-read the current state with Service.States, then subscribe again.
type Hub struct {
	mu   sync.Mutex
	subs map[*Subscription]struct{}
}

// Subscription receives Events on C until it is closed by Close or because it lagged.
type Subscription struct {
	// C yields events in publication order. It is closed when the subscription ends.
	C      <-chan Event
	ch     chan Event
	hub    *Hub
	lagged bool
	done   bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*Subscription]struct{}{}} }

// Subscribe starts receiving events published from now on.
func (h *Hub) Subscribe() *Subscription {
	ch := make(chan Event, subscriberBuffer)
	s := &Subscription{C: ch, ch: ch, hub: h}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Close ends the subscription; it is safe to call repeatedly.
func (s *Subscription) Close() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.hub.dropLocked(s)
}

// Lagged reports whether the hub closed the subscription because the consumer was too slow.
// Read it after C is closed.
func (s *Subscription) Lagged() bool {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	return s.lagged
}

func (h *Hub) dropLocked(s *Subscription) {
	if s.done {
		return
	}
	s.done = true
	delete(h.subs, s)
	close(s.ch)
}

// Publish delivers e to every subscriber that has room.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		select {
		case s.ch <- e:
		default:
			s.lagged = true
			h.dropLocked(s)
		}
	}
}
