// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
)

// Notifier defaults.
const (
	DefaultQueueSize = 256
	DefaultWorkers   = 4
	// jobTimeout bounds one delivery including its retries.
	jobTimeout = 2 * time.Minute
)

// NotifierOptions configure the delivery queue.
type NotifierOptions struct {
	Channels  *Channels
	QueueSize int
	Workers   int
	Log       *slog.Logger
}

type job struct {
	channelID string
	msg       notify.Message
}

// NotifierStats are the queue's counters.
type NotifierStats struct {
	Enqueued, Dropped, Sent, Failed int64
	Queued                          int
}

// Notifier delivers notifications from a bounded queue with a fixed worker pool. A full queue
// drops the new message and counts it; the alert itself is already recorded. It implements Sink.
type Notifier struct {
	opts   NotifierOptions
	mu     sync.RWMutex
	closed bool
	queues []chan job // one per worker; a channel always maps to the same one, so its messages stay in order
	wg     sync.WaitGroup
	once   sync.Once

	enqueued, dropped, sent, failed atomic.Int64
}

// NewNotifier builds the queue; call Start to run the workers.
func NewNotifier(o NotifierOptions) *Notifier {
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.Workers <= 0 {
		o.Workers = DefaultWorkers
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	n := &Notifier{opts: o}
	per := (o.QueueSize + o.Workers - 1) / o.Workers
	for i := 0; i < o.Workers; i++ {
		n.queues = append(n.queues, make(chan job, per))
	}
	return n
}

// Start launches the workers. They run until Close drains the queue.
func (n *Notifier) Start() {
	n.once.Do(func() {
		for i := 0; i < n.opts.Workers; i++ {
			n.wg.Add(1)
			go n.worker(n.queues[i])
		}
	})
}

// Enqueue queues a message without blocking; false means it was dropped (queue full or closed).
func (n *Notifier) Enqueue(channelID string, m notify.Message) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.closed {
		return false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(channelID))
	select {
	case n.queues[int(h.Sum32())%len(n.queues)] <- job{channelID, m}:
		n.enqueued.Add(1)
		return true
	default:
		n.dropped.Add(1)
		n.opts.Log.Warn("notification dropped: queue full", "code", string(errcode.ALRSend007), "channel_id", channelID, "alert_id", m.AlertID, "kind", m.Kind)
		return false
	}
}

func (n *Notifier) worker(q <-chan job) {
	defer n.wg.Done()
	for j := range q {
		ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
		err := n.opts.Channels.Deliver(ctx, j.channelID, j.msg)
		cancel()
		switch {
		case err == nil:
			n.sent.Add(1)
		case errors.Is(err, ErrNotFound), errors.Is(err, ErrDisabled):
			n.failed.Add(1)
		default:
			n.failed.Add(1)
			n.opts.Log.Warn("notification failed", "code", string(sendCode(err)), "channel_id", j.channelID, "alert_id", j.msg.AlertID, "kind", j.msg.Kind)
		}
	}
}

// Close stops accepting messages, delivers what is queued and waits for the workers, at most
// timeout. It reports whether everything drained in time.
func (n *Notifier) Close(timeout time.Duration) bool {
	n.mu.Lock()
	if !n.closed {
		n.closed = true
		for _, q := range n.queues {
			close(q)
		}
	}
	n.mu.Unlock()
	done := make(chan struct{})
	go func() { n.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Stats returns the counters.
func (n *Notifier) Stats() NotifierStats {
	return NotifierStats{Enqueued: n.enqueued.Load(), Dropped: n.dropped.Load(), Sent: n.sent.Load(), Failed: n.failed.Load(), Queued: n.queued()}
}

func (n *Notifier) queued() int {
	t := 0
	for _, q := range n.queues {
		t += len(q)
	}
	return t
}
