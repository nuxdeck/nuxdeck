// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"errors"
	"sync"
	"time"
)

const (
	subscriberBuffer = 64
	// MaxSubscribers bounds live connections; each browser tab holds one.
	MaxSubscribers = 512
)

// ErrTooManySubscribers is returned by Subscribe when MaxSubscribers is reached.
var ErrTooManySubscribers = errors.New("too many live subscribers")

// Hub fans events out to live subscribers without ever blocking the publisher: a
// subscriber that falls behind gets a resync event and is closed, and reloads through REST.
type Hub struct {
	mu   sync.Mutex
	seq  uint64
	subs map[*Subscription]struct{}
	now  func() time.Time
}

// Subscription is one live consumer.
type Subscription struct {
	C    <-chan Event
	ch   chan Event
	hub  *Hub
	done bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*Subscription]struct{}{}, now: time.Now} }

// Subscribe starts receiving events published from now on.
func (h *Hub) Subscribe() (*Subscription, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= MaxSubscribers {
		return nil, ErrTooManySubscribers
	}
	ch := make(chan Event, subscriberBuffer)
	s := &Subscription{C: ch, ch: ch, hub: h}
	h.subs[s] = struct{}{}
	return s, nil
}

// Close ends the subscription. It is safe to call more than once.
func (s *Subscription) Close() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.hub.dropLocked(s)
}

func (h *Hub) dropLocked(s *Subscription) {
	if !s.done {
		s.done = true
		delete(h.subs, s)
		close(s.ch)
	}
}

// Publish delivers an event to every subscriber.
func (h *Hub) Publish(typ string, item any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	ev := Event{Seq: h.seq, Type: typ, At: h.now().UTC(), Item: item}
	for s := range h.subs {
		select {
		case s.ch <- ev:
		default:
			// Make room for the resync marker, then close: the consumer drains it and reloads.
			select {
			case <-s.ch:
			default:
			}
			s.ch <- Event{Seq: h.seq, Type: EventResync, At: ev.At}
			h.dropLocked(s)
		}
	}
}
