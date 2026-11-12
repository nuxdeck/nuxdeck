// SPDX-License-Identifier: AGPL-3.0-only

package logs

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// fakeAgents stands in for the gateway: it records what the broker sends to each agent.
type fakeAgents struct {
	mu      sync.Mutex
	sent    map[string][]*agentv1.ServerMessage
	offline map[string]bool
	busy    int // number of sends to refuse with ErrAgentBusy
}

func newFakeAgents() *fakeAgents {
	return &fakeAgents{sent: map[string][]*agentv1.ServerMessage{}, offline: map[string]bool{}}
}

func (f *fakeAgents) SendToAgent(id string, m *agentv1.ServerMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.offline[id] {
		return gateway.ErrAgentOffline
	}
	if f.busy > 0 {
		f.busy--
		return gateway.ErrAgentBusy
	}
	f.sent[id] = append(f.sent[id], m)
	return nil
}

func (f *fakeAgents) opens(id string) (out []*agentv1.OpenLogStream) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.sent[id] {
		if o := m.GetOpenLog(); o != nil {
			out = append(out, o)
		}
	}
	return out
}

func (f *fakeAgents) closes(id string) (out []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.sent[id] {
		if c := m.GetCloseLog(); c != nil {
			out = append(out, c.GetStreamId())
		}
	}
	return out
}

func chunk(streamID string, texts ...string) *agentv1.AgentMessage {
	var lines []*agentv1.LogLine
	for i, t := range texts {
		lines = append(lines, &agentv1.LogLine{TsUnixMs: int64(1000 + i), Source: agentv1.LogLine_SOURCE_STDERR, Text: []byte(t)})
	}
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_LogChunk{LogChunk: &agentv1.LogChunk{StreamId: streamID, Lines: lines}}}
}

func ended(streamID, code string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_LogEnded{LogEnded: &agentv1.LogStreamEnded{StreamId: streamID, Code: code}}}
}

func recv(t *testing.T, w *Watcher) Event {
	t.Helper()
	select {
	case ev, ok := <-w.C:
		if !ok {
			t.Fatal("channel closed")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no event within 2s")
		return Event{}
	}
}

var web = Target{AgentID: "agent-1", Kind: KindContainer, Source: "abc123"}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestFirstWatcherOpensAStreamWithinTwoSeconds(t *testing.T) { // LOG-1
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	start := time.Now()
	w, err := b.Watch("u1", web, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	opens := ag.opens("agent-1")
	if len(opens) != 1 || opens[0].GetContainerRuntimeId() != "abc123" || opens[0].GetTailLines() != 50 {
		t.Fatalf("opens = %v", opens)
	}
	b.HandleMessage("agent-1", chunk(opens[0].GetStreamId(), "boom"))
	ev := recv(t, w)
	if ev.Type != TypeLine || ev.Text != "boom" || ev.Stream != "stderr" || time.Since(start) > 2*time.Second {
		t.Fatalf("event = %+v after %s", ev, time.Since(start))
	}
}

func TestJournalSource(t *testing.T) { // LOG-2
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w, err := b.Watch("u1", Target{AgentID: "agent-1", Kind: KindJournal, Source: "nginx.service"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if o := ag.opens("agent-1"); len(o) != 1 || o[0].GetJournalUnit() != "nginx.service" {
		t.Fatalf("opens = %v", o)
	}
}

func TestFanOutAndLastWatcherClosesTheAgentStream(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w1, _ := b.Watch("u1", web, 10)
	w2, err := b.Watch("u2", web, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ag.opens("agent-1")); n != 1 {
		t.Fatalf("agent got %d open requests, want 1", n)
	}
	if n := recv(t, w2); n.Type != TypeNotice {
		t.Fatalf("second watcher should be told it joined late, got %+v", n)
	}
	id := ag.opens("agent-1")[0].GetStreamId()

	b.HandleMessage("agent-1", chunk(id, "one", "two"))
	for _, w := range []*Watcher{w1, w2} {
		if a, c := recv(t, w), recv(t, w); a.Text != "one" || c.Text != "two" {
			t.Fatalf("watcher got %q, %q", a.Text, c.Text)
		}
	}

	w1.Close()
	if len(ag.closes("agent-1")) != 0 || b.Streams() != 1 {
		t.Fatal("stream closed while a watcher remained")
	}
	w2.Close()
	w2.Close() // idempotent
	waitFor(t, func() bool { return len(ag.closes("agent-1")) == 1 })
	if got := ag.closes("agent-1")[0]; got != id || b.Streams() != 0 {
		t.Fatalf("closed %q, streams %d", got, b.Streams())
	}

	// A new watcher opens a fresh stream and sees none of the old lines.
	w3, _ := b.Watch("u1", web, 10)
	defer w3.Close()
	if n := len(ag.opens("agent-1")); n != 2 {
		t.Fatalf("opens = %d, want 2", n)
	}
	select {
	case ev := <-w3.C:
		t.Fatalf("unexpected replay: %+v", ev)
	default:
	}
}

func TestCloseRetriesWhileTheAgentQueueIsFull(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w, _ := b.Watch("u1", web, 1)
	ag.mu.Lock()
	ag.busy = 2
	ag.mu.Unlock()
	w.Close()
	waitFor(t, func() bool { return len(ag.closes("agent-1")) == 1 })
}

func TestSlowWatcherLosesLinesNotTheStream(t *testing.T) { // backpressure towards browsers
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag, WatcherQueue: 4})
	slow, _ := b.Watch("u1", web, 0)
	fast, _ := b.Watch("u2", web, 0)
	defer slow.Close()
	defer fast.Close()
	recv(t, fast) // join notice
	id := ag.opens("agent-1")[0].GetStreamId()

	done := make(chan struct{})
	go func() { // the broker must never block on a slow consumer
		defer close(done)
		for i := range 100 {
			b.HandleMessage("agent-1", chunk(id, "l"+strconv.Itoa(i)))
			recv(t, fast)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("broker blocked on a slow watcher")
	}

	// Drain the slow watcher: it holds at most its queue, and the loss is announced.
	for range 3 {
		recv(t, slow)
	}
	b.HandleMessage("agent-1", chunk(id, "after"))
	var notice Event
	for ev := range drain(slow) {
		if ev.Type == TypeNotice && ev.Dropped > 0 {
			notice = ev
		}
	}
	if notice.Code != string(errcode.LOGStr003) || notice.Dropped == 0 {
		t.Fatalf("no drop notice, got %+v", notice)
	}
}

func drain(w *Watcher) <-chan Event {
	out := make(chan Event, 16)
	go func() {
		defer close(out)
		for {
			select {
			case ev := <-w.C:
				out <- ev
			case <-time.After(50 * time.Millisecond):
				return
			}
		}
	}()
	return out
}

func TestEndAlwaysReachesAFullQueue(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag, WatcherQueue: 2})
	w, _ := b.Watch("u1", web, 0)
	id := ag.opens("agent-1")[0].GetStreamId()
	b.HandleMessage("agent-1", chunk(id, "a", "b", "c", "d"))
	b.HandleMessage("agent-1", ended(id, "LOG-SRC-001"))

	var last Event
	for ev := range w.C { // the channel closes after the end event
		last = ev
	}
	if last.Type != TypeEnd || last.Reason != ReasonSourceError || last.Code != "LOG-SRC-001" {
		t.Fatalf("last = %+v", last)
	}
	w.Close()
	if b.Streams() != 0 || len(ag.closes("agent-1")) != 0 {
		t.Fatal("an ended stream must not be closed again")
	}
}

func TestEndCodesFromAgentsAreSanitised(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w, _ := b.Watch("u1", web, 0)
	b.HandleMessage("agent-1", ended(ag.opens("agent-1")[0].GetStreamId(), "<script>alert(1)</script>"))
	if ev := recv(t, w); ev.Code != string(errcode.LOGSrc001) {
		t.Fatalf("code = %q", ev.Code)
	}
}

func TestAnAgentCannotWriteIntoAnotherAgentsStream(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w, _ := b.Watch("u1", web, 0)
	defer w.Close()
	id := ag.opens("agent-1")[0].GetStreamId()
	b.HandleMessage("agent-2", chunk(id, "forged"))
	b.HandleMessage("agent-2", ended(id, ""))
	select {
	case ev := <-w.C:
		t.Fatalf("forged message delivered: %+v", ev)
	default:
	}
	if b.Streams() != 1 {
		t.Fatal("forged end tore the stream down")
	}
}

func TestLimits(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag, MaxStreams: 3, MaxPerAgent: 2, MaxPerUser: 3})
	watch := func(user, agent, src string) error {
		_, err := b.Watch(user, Target{AgentID: agent, Kind: KindContainer, Source: src}, 0)
		return err
	}
	for _, src := range []string{"a", "b"} {
		if err := watch("u1", "agent-1", src); err != nil {
			t.Fatal(err)
		}
	}
	if err := watch("u2", "agent-1", "c"); !errors.Is(err, ErrLimit) {
		t.Errorf("per-agent limit: err = %v", err)
	}
	if err := watch("u2", "agent-2", "c"); err != nil {
		t.Fatal(err)
	}
	if err := watch("u3", "agent-3", "d"); !errors.Is(err, ErrLimit) {
		t.Errorf("global limit: err = %v", err)
	}
	if err := watch("u1", "agent-2", "c"); err != nil { // joins an existing stream: no new stream needed
		t.Fatal(err)
	}
	if err := watch("u1", "agent-2", "c"); !errors.Is(err, ErrLimit) {
		t.Errorf("per-user limit: err = %v", err)
	}
	if errcode.CodeOf(ErrLimit) != errcode.LOGStr001 {
		t.Error("ErrLimit must carry LOG-STR-001")
	}
}

func TestOfflineAgent(t *testing.T) {
	ag := newFakeAgents()
	ag.offline["agent-1"] = true
	b := NewBroker(Options{Sender: ag})
	if _, err := b.Watch("u1", web, 0); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("err = %v", err)
	}
	if b.Streams() != 0 {
		t.Fatal("a failed open must leave no stream behind")
	}
	// ...and must not consume the user's quota.
	ag.offline["agent-1"] = false
	for range DefaultMaxPerUser {
		if _, err := b.Watch("u1", Target{AgentID: "agent-1", Kind: KindContainer, Source: "x"}, 0); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAgentGoneEndsStreams(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w, _ := b.Watch("u1", web, 0)
	keep, _ := b.Watch("u1", Target{AgentID: "agent-2", Kind: KindContainer, Source: "z"}, 0)
	defer keep.Close()
	b.AgentGone("agent-1")
	if ev := recv(t, w); ev.Type != TypeEnd || ev.Reason != ReasonAgentOffline {
		t.Fatalf("event = %+v", ev)
	}
	if b.Streams() != 1 {
		t.Fatalf("streams = %d, want 1", b.Streams())
	}
}

func TestEventJSON(t *testing.T) {
	cases := map[string]Event{
		`{"type":"line","ts":1000,"stream":"stdout","text":""}`:                {Type: TypeLine, TS: 1000, Stream: "stdout"},
		`{"type":"line","ts":5,"stream":"stderr","text":"a\"b"}`:               {Type: TypeLine, TS: 5, Stream: "stderr", Text: `a"b`},
		`{"type":"notice","code":"LOG-STR-003","message":"m","dropped":3}`:     {Type: TypeNotice, Code: "LOG-STR-003", Message: "m", Dropped: 3},
		`{"type":"end","reason":"source_error","code":"LOG-SRC-001"}`:          {Type: TypeEnd, Reason: ReasonSourceError, Code: "LOG-SRC-001"},
		`{"type":"end","reason":"source_ended"}`:                               {Type: TypeEnd, Reason: ReasonSourceEnded},
		`{"type":"line","ts":1,"stream":"journal","text":"bad � utf8"}`:        {Type: TypeLine, TS: 1, Stream: "journal", Text: "bad \xff utf8"},
		`{"type":"notice","message":"Joined"}`:                                 {Type: TypeNotice, Message: "Joined"},
		`{"type":"line","ts":1,"stream":"stdout","text":"\u003cscript\u003e"}`: {Type: TypeLine, TS: 1, Stream: "stdout", Text: "<script>"},
	}
	for want, ev := range cases {
		got, err := json.Marshal(ev)
		if err != nil || string(got) != want {
			t.Errorf("got %s (%v), want %s", got, err, want)
		}
	}
}

// LOG-6: lines live in memory only. The package may not touch storage or files, and a run
// through the broker must leave nothing on disk.
func TestNothingIsPersisted(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			switch {
			case p == "os", p == "io/ioutil", p == "io/fs", p == "database/sql", strings.HasSuffix(p, "/store"), strings.HasPrefix(p, "modernc.org"):
				t.Errorf("%s imports %s: log lines must never be stored", name, p)
			}
		}
	}

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("TMPDIR", dir)
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag})
	w, _ := b.Watch("u1", web, 100)
	id := ag.opens("agent-1")[0].GetStreamId()
	for i := range 1000 {
		b.HandleMessage("agent-1", chunk(id, "secret-line-"+strconv.Itoa(i)))
	}
	w.Close()
	b.Close()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("broker wrote %d files", len(entries))
	}
}

func TestLongLinesAndOversizedChunksAreBounded(t *testing.T) {
	ag := newFakeAgents()
	b := NewBroker(Options{Sender: ag, WatcherQueue: 2000})
	w, _ := b.Watch("u1", web, 0)
	defer w.Close()
	id := ag.opens("agent-1")[0].GetStreamId()
	texts := make([]string, 700)
	texts[0] = strings.Repeat("x", 5*MaxLineBytes)
	b.HandleMessage("agent-1", chunk(id, texts...))
	if ev := recv(t, w); len(ev.Text) != MaxLineBytes {
		t.Fatalf("line of %d bytes passed", len(ev.Text))
	}
	n := 1
	for len(w.C) > 0 {
		<-w.C
		n++
	}
	if n != maxChunkLine {
		t.Fatalf("%d lines delivered from one chunk, want %d", n, maxChunkLine)
	}
}
