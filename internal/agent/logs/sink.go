// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"context"
	"sync"
	"time"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// lineOverhead approximates the protobuf cost of a line besides its text.
const lineOverhead = 16

// sink batches lines into LogChunk messages of at most MaxChunkLines lines or MaxChunkBytes
// bytes. A full chunk is handed over with a blocking send, so a source that calls add faster
// than the link drains simply waits there: backpressure reaches the reader.
type sink struct {
	ctx context.Context
	id  string
	out chan<- *agentv1.AgentMessage

	mu    sync.Mutex
	lines []*agentv1.LogLine
	bytes int
	done  chan struct{}
	wg    sync.WaitGroup
}

func newSink(ctx context.Context, id string, out chan<- *agentv1.AgentMessage, flush time.Duration) *sink {
	s := &sink{ctx: ctx, id: id, out: out, done: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(flush)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.mu.Lock()
				s.flushLocked()
				s.mu.Unlock()
			case <-s.done:
				return
			}
		}
	}()
	return s
}

// add queues a line, truncated to MaxLineBytes, and returns the context's error once the
// stream is closed.
func (s *sink) add(ts time.Time, source agentv1.LogLine_Source, text []byte) error {
	if len(text) > MaxLineBytes {
		text = text[:MaxLineBytes]
	}
	line := &agentv1.LogLine{TsUnixMs: ts.UnixMilli(), Source: source, Text: append([]byte(nil), text...)}
	size := len(text) + lineOverhead

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytes+size > MaxChunkBytes {
		s.flushLocked()
	}
	s.lines = append(s.lines, line)
	s.bytes += size
	if len(s.lines) >= MaxChunkLines || s.bytes >= MaxChunkBytes {
		s.flushLocked()
	}
	return s.ctx.Err()
}

// flushLocked sends the pending chunk. The mutex stays held while it waits, which is what
// stalls add. Context cancellation releases it.
func (s *sink) flushLocked() {
	if len(s.lines) == 0 {
		return
	}
	msg := &agentv1.AgentMessage{Body: &agentv1.AgentMessage_LogChunk{LogChunk: &agentv1.LogChunk{StreamId: s.id, Lines: s.lines}}}
	s.lines, s.bytes = nil, 0
	select {
	case s.out <- msg:
	case <-s.ctx.Done():
	}
}

// Close sends what is pending and stops the timer.
func (s *sink) Close() {
	close(s.done)
	s.wg.Wait()
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()
}
