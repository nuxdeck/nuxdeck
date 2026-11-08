// SPDX-License-Identifier: AGPL-3.0-only

// Package logs brokers live log streams between browsers and agents. A stream to an agent
// is opened when the first watcher of a source arrives and closed when the last one leaves;
// every other watcher of the same source shares it. Lines pass through memory only: this
// package has no storage, no file access and no replay buffer (LOG-6).
package logs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Source kinds of a Target.
const (
	KindContainer = "container"
	KindJournal   = "journal"
)

// Defaults for Options.
const (
	DefaultMaxStreams   = 64
	DefaultMaxPerAgent  = 8
	DefaultMaxPerUser   = 10
	DefaultWatcherQueue = 256
	// MaxLineBytes caps one line from an agent; agents are authenticated but not trusted.
	MaxLineBytes = 16 << 10
	maxChunkLine = 500
)

// Errors returned by Watch.
var (
	// ErrLimit means a per-user, per-agent or global stream limit is reached (LOG-STR-001).
	ErrLimit = errcode.New(errcode.LOGStr001, "live log stream limit reached")
	// ErrAgentOffline means the host's agent is not connected (LOG-SRC-003).
	ErrAgentOffline = errcode.New(errcode.LOGSrc003, "agent not connected")
)

// Sender delivers a message to an agent's live stream without blocking; *gateway.Gateway
// implements it through SendToAgent.
type Sender interface {
	SendToAgent(agentID string, m *agentv1.ServerMessage) error
}

// Options configure a Broker.
type Options struct {
	Sender Sender
	Log    *slog.Logger
	// MaxStreams caps agent streams across all agents; MaxPerAgent per agent; MaxPerUser
	// counts a user's watchers. Zero means the default.
	MaxStreams, MaxPerAgent, MaxPerUser int
	// WatcherQueue is the per-watcher buffer of events; a watcher that falls further
	// behind loses lines and is told so.
	WatcherQueue int
}

// Target names a log source on a host.
type Target struct {
	AgentID string
	Kind    string // KindContainer or KindJournal
	Source  string // container runtime ID, or systemd unit
}

func (t Target) key() string { return t.AgentID + "|" + t.Kind + "|" + t.Source }

// Broker fans agent log streams out to watchers.
type Broker struct {
	o   Options
	log *slog.Logger

	mu      sync.Mutex
	byKey   map[string]*stream
	byID    map[string]*stream
	perUser map[string]int
	perAg   map[string]int
	closed  bool
}

type stream struct {
	id       string
	target   Target
	watchers map[*Watcher]struct{}
}

// NewBroker returns an empty broker.
func NewBroker(o Options) *Broker {
	if o.MaxStreams <= 0 {
		o.MaxStreams = DefaultMaxStreams
	}
	if o.MaxPerAgent <= 0 {
		o.MaxPerAgent = DefaultMaxPerAgent
	}
	if o.MaxPerUser <= 0 {
		o.MaxPerUser = DefaultMaxPerUser
	}
	if o.WatcherQueue <= 0 {
		o.WatcherQueue = DefaultWatcherQueue
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Broker{o: o, log: o.Log, byKey: map[string]*stream{}, byID: map[string]*stream{}, perUser: map[string]int{}, perAg: map[string]int{}}
}

// Watcher is one consumer of a stream. Read events from C until it is closed; the last
// event before the close is always an end event. Call Close when done reading.
type Watcher struct {
	C <-chan Event

	b       *Broker
	st      *stream
	user    string
	ch      chan Event
	dropped int // lines lost since the last notice; guarded by b.mu
	done    bool
}

// Watch attaches userID to the stream for t, opening it on the agent if nobody watches yet.
// tail is the history to request when the stream is new; a watcher that joins a running stream
// sees lines from that moment on, because nothing is stored to replay.
func (b *Broker) Watch(userID string, t Target, tail uint32) (*Watcher, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrAgentOffline
	}
	if b.perUser[userID] >= b.o.MaxPerUser {
		return nil, ErrLimit
	}

	ch := make(chan Event, b.o.WatcherQueue)
	w := &Watcher{C: ch, ch: ch, b: b, user: userID}
	if st := b.byKey[t.key()]; st != nil {
		w.st = st
		st.watchers[w] = struct{}{}
		b.perUser[userID]++
		w.send(Event{Type: TypeNotice, Message: "Joined a live stream that was already open; earlier lines are not shown."})
		return w, nil
	}

	if len(b.byID) >= b.o.MaxStreams || b.perAg[t.AgentID] >= b.o.MaxPerAgent {
		return nil, ErrLimit
	}
	st := &stream{id: newStreamID(), target: t, watchers: map[*Watcher]struct{}{w: {}}}
	open := &agentv1.OpenLogStream{StreamId: st.id, TailLines: tail}
	if t.Kind == KindJournal {
		open.Source = &agentv1.OpenLogStream_JournalUnit{JournalUnit: t.Source}
	} else {
		open.Source = &agentv1.OpenLogStream_ContainerRuntimeId{ContainerRuntimeId: t.Source}
	}
	if err := b.o.Sender.SendToAgent(t.AgentID, &agentv1.ServerMessage{Body: &agentv1.ServerMessage_OpenLog{OpenLog: open}}); err != nil {
		return nil, ErrAgentOffline
	}
	w.st = st
	b.byKey[t.key()], b.byID[st.id] = st, st
	b.perAg[t.AgentID]++
	b.perUser[userID]++
	return w, nil
}

// Close detaches the watcher; the last one out closes the agent's stream. It is safe to call twice.
func (w *Watcher) Close() {
	b := w.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if w.done {
		return
	}
	w.done = true
	b.perUser[w.user]--
	if b.perUser[w.user] <= 0 {
		delete(b.perUser, w.user)
	}
	st := w.st
	if _, ok := st.watchers[w]; !ok {
		return // the stream already ended
	}
	delete(st.watchers, w)
	if len(st.watchers) == 0 {
		b.removeLocked(st)
		go b.sendClose(st)
	}
}

// sendClose asks the agent to stop, retrying while its send queue is full. An offline agent
// has nothing left to stop.
func (b *Broker) sendClose(st *stream) {
	msg := &agentv1.ServerMessage{Body: &agentv1.ServerMessage_CloseLog{CloseLog: &agentv1.CloseLogStream{StreamId: st.id}}}
	for range 50 {
		err := b.o.Sender.SendToAgent(st.target.AgentID, msg)
		if !errors.Is(err, gateway.ErrAgentBusy) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.log.Warn("could not tell an agent to close a log stream", "agent_id", st.target.AgentID)
}

func (b *Broker) removeLocked(st *stream) {
	delete(b.byKey, st.target.key())
	delete(b.byID, st.id)
	if b.perAg[st.target.AgentID]--; b.perAg[st.target.AgentID] <= 0 {
		delete(b.perAg, st.target.AgentID)
	}
}

// HandleMessage consumes LogChunk and LogStreamEnded from an agent. It never blocks.
// Messages for a stream that belongs to another agent are ignored.
func (b *Broker) HandleMessage(agentID string, m *agentv1.AgentMessage) {
	switch body := m.GetBody().(type) {
	case *agentv1.AgentMessage_LogChunk:
		b.chunk(agentID, body.LogChunk)
	case *agentv1.AgentMessage_LogEnded:
		b.mu.Lock()
		defer b.mu.Unlock()
		st := b.byID[body.LogEnded.GetStreamId()]
		if st == nil || st.target.AgentID != agentID {
			return
		}
		ev := Event{Type: TypeEnd, Reason: ReasonSourceEnded}
		if code := body.LogEnded.GetCode(); code != "" {
			ev.Reason, ev.Code = ReasonSourceError, sanitizeCode(code)
		}
		b.endLocked(st, ev)
	}
}

func (b *Broker) chunk(agentID string, c *agentv1.LogChunk) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.byID[c.GetStreamId()]
	if st == nil || st.target.AgentID != agentID {
		return
	}
	lines := c.GetLines()
	if len(lines) > maxChunkLine {
		lines = lines[:maxChunkLine]
	}
	for _, l := range lines {
		text := l.GetText()
		if len(text) > MaxLineBytes {
			text = text[:MaxLineBytes]
		}
		ev := Event{Type: TypeLine, TS: l.GetTsUnixMs(), Stream: streamName(l.GetSource()), Text: strings.ToValidUTF8(string(text), "�")}
		for w := range st.watchers {
			w.send(ev)
		}
	}
}

// AgentGone ends every stream of an agent whose connection ended or was replaced.
func (b *Broker) AgentGone(agentID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, st := range b.byID {
		if st.target.AgentID == agentID {
			b.endLocked(st, Event{Type: TypeEnd, Reason: ReasonAgentOffline, Code: string(errcode.LOGSrc003)})
		}
	}
}

// Close ends every stream and refuses new watchers; call it when the server shuts down.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for _, st := range b.byID {
		b.endLocked(st, Event{Type: TypeEnd, Reason: ReasonServerShutdown})
		go b.sendClose(st)
	}
}

// Streams reports how many agent streams are open, for metrics and tests.
func (b *Broker) Streams() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.byID)
}

// endLocked delivers ev to every watcher, closes their channels and forgets the stream.
func (b *Broker) endLocked(st *stream, ev Event) {
	b.removeLocked(st)
	for w := range st.watchers {
		w.end(ev)
	}
	st.watchers = map[*Watcher]struct{}{}
}

// send queues ev without blocking. When the queue is full the line is dropped and counted;
// the next event that fits is preceded by a notice saying how many were lost.
func (w *Watcher) send(ev Event) {
	if w.dropped > 0 {
		note := Event{Type: TypeNotice, Code: string(errcode.LOGStr003), Message: "Your connection could not keep up; some lines were dropped.", Dropped: w.dropped}
		select {
		case w.ch <- note:
			w.dropped = 0
		default:
		}
	}
	select {
	case w.ch <- ev:
	default:
		if ev.Type == TypeLine {
			w.dropped++
		}
	}
}

// end delivers the final event, making room if the queue is full, then closes the channel.
func (w *Watcher) end(ev Event) {
	for {
		select {
		case w.ch <- ev:
			close(w.ch)
			return
		default:
		}
		select {
		case <-w.ch: // the consumer is behind: its oldest event makes way for the end
		default:
		}
	}
}

func newStreamID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func streamName(s agentv1.LogLine_Source) string {
	switch s {
	case agentv1.LogLine_SOURCE_STDERR:
		return "stderr"
	case agentv1.LogLine_SOURCE_JOURNAL:
		return "journal"
	default:
		return "stdout"
	}
}

// sanitizeCode passes only a stable error code from an agent on to browsers.
func sanitizeCode(code string) string {
	if len(code) <= 16 && strings.HasPrefix(code, "LOG-") && strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") == "" {
		return code
	}
	return string(errcode.LOGSrc001)
}
