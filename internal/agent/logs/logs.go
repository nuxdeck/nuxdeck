// SPDX-License-Identifier: Apache-2.0

// Package logs streams container and systemd journal logs to nuxd, but only while the server
// asks for them (LOG-6). A stream starts on OpenLogStream and ends on CloseLogStream, on a
// disconnect or when its source ends; nothing is buffered on disk. The package reads and
// never changes anything on the host (ADR-010): containers are read through nux-sockguard's
// socket only (ADR-011) and the journal through a fixed, argument-validated journalctl.
package logs

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Limits of one agent. The server is authenticated but its requests are still bounded.
const (
	// MaxChunkLines and MaxChunkBytes are the protocol's LogChunk limits.
	MaxChunkLines = 500
	MaxChunkBytes = 256 << 10
	// MaxLineBytes caps one log line; the rest of a longer line is dropped.
	MaxLineBytes = 16 << 10
	// MaxTail caps how much history a stream may replay.
	MaxTail = 10000

	defaultMaxStreams = 8
	defaultFlush      = 100 * time.Millisecond
	// DefaultSockguardSocket is the only socket the agent talks to for containers.
	DefaultSockguardSocket = "/run/nux/sockguard.sock"
)

var streamIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Config configures a Manager.
type Config struct {
	// SockguardSocket defaults to DefaultSockguardSocket.
	SockguardSocket string
	// JournalctlPath overrides the located journalctl; tests use it.
	JournalctlPath string
	// MaxStreams caps concurrent streams (default 8).
	MaxStreams int
	// FlushInterval is how long a partial chunk waits for more lines (default 100 ms).
	FlushInterval time.Duration
	Log           *slog.Logger
}

// Manager owns the streams of one agent connection.
type Manager struct {
	cfg    Config
	docker *dockerClient
	out    chan *agentv1.AgentMessage

	mu      sync.Mutex
	streams map[string]context.CancelFunc
	wg      sync.WaitGroup
}

// New returns a Manager; it does nothing until Open is called.
func New(cfg Config) *Manager {
	if cfg.SockguardSocket == "" {
		cfg.SockguardSocket = DefaultSockguardSocket
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = defaultMaxStreams
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlush
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		cfg:     cfg,
		docker:  newDockerClient(cfg.SockguardSocket),
		out:     make(chan *agentv1.AgentMessage), // unbuffered: a slow gRPC stream stops the sources
		streams: map[string]context.CancelFunc{},
	}
}

// Out carries LogChunk and LogStreamEnded messages for the connection loop to send. Reading
// from it at the pace of gRPC flow control is what makes sources stop when the link is slow.
func (m *Manager) Out() <-chan *agentv1.AgentMessage { return m.out }

// Open starts a stream for o. It never blocks and never fails the connection: a request that
// cannot be served is answered with LogStreamEnded carrying a stable code.
func (m *Manager) Open(ctx context.Context, o *agentv1.OpenLogStream) {
	id := o.GetStreamId()
	if !streamIDPattern.MatchString(id) {
		m.cfg.Log.Warn("ignoring log stream with an invalid ID")
		return
	}
	run, err := m.source(o)

	m.mu.Lock()
	_, dup := m.streams[id]
	switch {
	case dup:
		m.mu.Unlock()
		m.cfg.Log.Warn("ignoring duplicate log stream", "stream_id", id)
		return
	case err == nil && len(m.streams) >= m.cfg.MaxStreams:
		err = errcode.New(errcode.LOGStr001, "agent already serves %d streams", m.cfg.MaxStreams)
	}
	if err != nil {
		m.mu.Unlock()
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.end(ctx, id, err)
		}()
		return
	}
	sctx, cancel := context.WithCancel(ctx)
	m.streams[id] = cancel
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		defer cancel()
		sink := newSink(sctx, id, m.out, m.cfg.FlushInterval)
		err := run(sctx, sink)
		sink.Close()
		m.mu.Lock()
		delete(m.streams, id)
		m.mu.Unlock()
		if sctx.Err() != nil {
			return // closed by the server or the connection: nobody is waiting for an end message
		}
		m.end(ctx, id, err)
	}()
}

// Close stops one stream; unknown IDs are ignored.
func (m *Manager) Close(id string) {
	m.mu.Lock()
	cancel := m.streams[id]
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// CloseAll stops every stream, waits until their sources are released and discards messages
// that were not sent. Call it when the connection ends.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	for _, cancel := range m.streams {
		cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// end reports that a stream is over; code is empty for a normal end of the source.
func (m *Manager) end(ctx context.Context, id string, err error) {
	var code string
	if err != nil {
		c := errcode.CodeOf(err)
		if c == "" {
			c = errcode.LOGSrc001
		}
		code = string(c)
		m.cfg.Log.Warn("log stream ended with an error", "stream_id", id, "code", code, "error", err)
	}
	msg := &agentv1.AgentMessage{Body: &agentv1.AgentMessage_LogEnded{LogEnded: &agentv1.LogStreamEnded{StreamId: id, Code: code}}}
	select {
	case m.out <- msg:
	case <-ctx.Done():
	}
}

type runFunc func(ctx context.Context, s *sink) error

// source validates the request and picks the reader. Validation happens here, before any
// process starts or request is made.
func (m *Manager) source(o *agentv1.OpenLogStream) (runFunc, error) {
	tail := min(o.GetTailLines(), MaxTail)
	since := o.GetSinceUnixMs()
	if since < 0 {
		return nil, errcode.New(errcode.LOGStr002, "negative since")
	}
	switch src := o.GetSource().(type) {
	case *agentv1.OpenLogStream_ContainerRuntimeId:
		if !containerIDPattern.MatchString(src.ContainerRuntimeId) {
			return nil, errcode.New(errcode.LOGStr002, "invalid container ID")
		}
		return func(ctx context.Context, s *sink) error {
			return m.docker.stream(ctx, src.ContainerRuntimeId, tail, since, s)
		}, nil
	case *agentv1.OpenLogStream_JournalUnit:
		if err := ValidateUnit(src.JournalUnit); err != nil {
			return nil, errcode.Wrap(errcode.LOGStr002, "journal unit", err)
		}
		return func(ctx context.Context, s *sink) error {
			return streamJournal(ctx, m.cfg.JournalctlPath, src.JournalUnit, tail, since, s)
		}, nil
	default:
		return nil, errors.New("no log source")
	}
}
