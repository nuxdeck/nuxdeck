// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

func frame(kind byte, payload string) []byte {
	h := make([]byte, 8)
	h[0] = kind
	binary.BigEndian.PutUint32(h[4:], uint32(len(payload))) //nolint:gosec // test payloads are tiny
	return append(h, payload...)
}

const stamp = "2026-10-26T10:00:00.123456789Z "

// collect gathers (source, text) pairs from a sink run.
func collect(t *testing.T, run func(s *sink) error) []string {
	t.Helper()
	out := make(chan *agentv1.AgentMessage, 64)
	ctx := t.Context()
	s := newSink(ctx, "s1", out, time.Hour)
	if err := run(s); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("run: %v", err)
	}
	s.Close()
	close(out)
	var got []string
	for m := range out {
		for _, l := range m.GetLogChunk().GetLines() {
			got = append(got, fmt.Sprintf("%d:%s", l.GetSource(), l.GetText()))
		}
	}
	return got
}

func TestDemuxSplitsStreamsAndJoinsPartialLines(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(1, stamp+"hel"))
	in.Write(frame(2, stamp+"err one\n"))
	in.Write(frame(1, "lo\n"+stamp+"second\n"))
	in.Write(frame(2, stamp+"err two\r\n"))
	got := collect(t, func(s *sink) error {
		return demux(&in, s)
	})
	want := []string{"2:err one", "1:hello", "1:second", "2:err two"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestDemuxRejectsMalformedFrames(t *testing.T) {
	cases := map[string][]byte{
		"unknown stream type": frame(7, "x\n"),
		"nonzero padding":     append([]byte{1, 9, 0, 0, 0, 0, 0, 1}, 'x'),
		"oversized frame":     {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSink(t.Context(), "s", make(chan *agentv1.AgentMessage, 1), time.Hour)
			defer s.Close()
			if err := demux(bytes.NewReader(b), s); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("err = %v, want a framing error", err)
			}
		})
	}
}

func TestRawTTYStreamHasNoFraming(t *testing.T) {
	// A payload that looks like a frame header must stay text on a TTY.
	in := strings.NewReader(stamp + "\x01\x00\x00\x00\x00\x00\x00\x05 prompt\n" + stamp + "next\n")
	got := collect(t, func(s *sink) error { return readRaw(in, s) })
	if len(got) != 2 || got[1] != "1:next" {
		t.Fatalf("lines = %q", got)
	}
}

func TestLongLinesAreTruncated(t *testing.T) {
	in := strings.NewReader(stamp + strings.Repeat("a", 5*MaxLineBytes) + "\n" + stamp + "ok\n")
	got := collect(t, func(s *sink) error { return readRaw(in, s) })
	if len(got) != 2 || len(got[0]) > MaxLineBytes+4 || got[1] != "1:ok" {
		t.Fatalf("got %d lines, first %d bytes", len(got), len(got[0]))
	}
}

func TestLineWithoutTimestampKeepsText(t *testing.T) {
	got := collect(t, func(s *sink) error { return readRaw(strings.NewReader("plain text here\n"), s) })
	if len(got) != 1 || got[0] != "1:plain text here" {
		t.Fatalf("lines = %q", got)
	}
}

func TestSinkChunkLimits(t *testing.T) {
	out := make(chan *agentv1.AgentMessage, 64)
	s := newSink(t.Context(), "s1", out, time.Hour)
	for range 1200 {
		_ = s.add(time.Now(), agentv1.LogLine_SOURCE_STDOUT, []byte("x"))
	}
	big := bytes.Repeat([]byte("y"), MaxLineBytes)
	for range 40 {
		_ = s.add(time.Now(), agentv1.LogLine_SOURCE_STDOUT, big)
	}
	s.Close()
	close(out)
	total := 0
	for m := range out {
		n, size := len(m.GetLogChunk().GetLines()), 0
		for _, l := range m.GetLogChunk().GetLines() {
			size += len(l.GetText())
		}
		if n > MaxChunkLines || size > MaxChunkBytes {
			t.Errorf("chunk of %d lines and %d bytes exceeds the limits", n, size)
		}
		total += n
	}
	if total != 1240 {
		t.Errorf("total lines = %d, want 1240", total)
	}
}

func TestValidateUnit(t *testing.T) {
	for _, ok := range []string{"nginx", "nginx.service", "user@1000.service", "getty@tty1.service", "systemd-resolved.service", "a:b.mount"} {
		if err := ValidateUnit(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	bad := []string{
		"", "-f", "--output=export", "-u", "--vacuum-size=1", "nginx; rm -rf /", "nginx && id", "$(id)", "`id`",
		"a b", "a\nb", "a\x00b", "../etc/passwd", "/etc/passwd", "nginx.service --since=x", "*", "ngi*", "[a]", "a\\x2db",
		".hidden", "_x", "unit|cat", "unit>out", "ünit", strings.Repeat("a", 256),
	}
	for _, u := range bad {
		if err := ValidateUnit(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestJournalArgsKeepUnitInOneElement(t *testing.T) {
	args := journalArgs("nginx.service", 50, 0)
	if got := args[len(args)-2:]; got[0] != "--unit=nginx.service" || got[1] != "--lines=50" {
		t.Fatalf("args = %q", args)
	}
	if got := strings.Join(journalArgs("x", 5, 1700000000123), " "); !strings.Contains(got, "--since=@1700000000") {
		t.Fatalf("args = %s", got)
	}
}

// fakeSockguard serves the container API on a Unix socket and records every request.
type fakeSockguard struct {
	sock string
	tty  bool
	logs func(w http.ResponseWriter, r *http.Request)

	mu       sync.Mutex
	requests []string
}

func newFakeSockguard(t *testing.T, logs func(w http.ResponseWriter, r *http.Request)) *fakeSockguard {
	t.Helper()
	f := &fakeSockguard{sock: filepath.Join(t.TempDir(), "sg.sock"), logs: logs}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch {
		case logs == nil:
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/json"):
			_, _ = fmt.Fprintf(w, `{"Config":{"Tty":%t}}`, f.tty)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			f.logs(w, r)
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func open(id, container string) *agentv1.OpenLogStream {
	return &agentv1.OpenLogStream{StreamId: id, Source: &agentv1.OpenLogStream_ContainerRuntimeId{ContainerRuntimeId: container}, TailLines: 10}
}

func next(t *testing.T, m *Manager) *agentv1.AgentMessage {
	t.Helper()
	select {
	case msg := <-m.Out():
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("no message within 2s")
		return nil
	}
}

func TestContainerStreamStartsAndEnds(t *testing.T) { // LOG-1
	f := newFakeSockguard(t, func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("follow") != "1" || q.Get("tail") != "10" || q.Get("since") != "1700000000.123" {
			t.Errorf("query = %v", q)
		}
		_, _ = w.Write(frame(1, stamp+"hello\n"))
		_, _ = w.Write(frame(2, stamp+"oops\n"))
	})
	m := New(Config{SockguardSocket: f.sock, FlushInterval: 10 * time.Millisecond})
	o := open("s1", "abc123")
	o.SinceUnixMs = 1700000000123
	start := time.Now()
	m.Open(t.Context(), o)

	chunk := next(t, m).GetLogChunk()
	if time.Since(start) > 2*time.Second || chunk.GetStreamId() != "s1" {
		t.Fatalf("chunk = %v after %s", chunk, time.Since(start))
	}
	lines := chunk.GetLines()
	if len(lines) < 1 || string(lines[0].GetText()) != "hello" || lines[0].GetSource() != agentv1.LogLine_SOURCE_STDOUT {
		t.Fatalf("lines = %v", lines)
	}
	if lines[0].GetTsUnixMs() != time.Date(2026, 10, 26, 10, 0, 0, 123456789, time.UTC).UnixMilli() {
		t.Errorf("timestamp not parsed: %d", lines[0].GetTsUnixMs())
	}
	var ended *agentv1.LogStreamEnded
	for ended == nil {
		ended = next(t, m).GetLogEnded()
	}
	if ended.GetStreamId() != "s1" || ended.GetCode() != "" {
		t.Errorf("ended = %v, want a normal end", ended)
	}
}

func TestADR010OnlyReadOnlySockguardRequests(t *testing.T) {
	f := newFakeSockguard(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(frame(1, stamp+"x\n")) })
	m := New(Config{SockguardSocket: f.sock, FlushInterval: 5 * time.Millisecond})
	m.Open(t.Context(), open("s1", "web-1"))
	for ended := false; !ended; {
		ended = next(t, m).GetLogEnded() != nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	want := []string{"GET /containers/web-1/json", "GET /containers/web-1/logs"}
	if strings.Join(f.requests, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", f.requests, want)
	}
}

func TestPackageHasNoWritePathsOrForbiddenImports(t *testing.T) { // ADR-010, ADR-011, licence boundary
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		src, err := os.ReadFile(name) //nolint:gosec // package source
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(p, "internal/server") || strings.Contains(p, "cmd/nuxd") {
				t.Errorf("%s imports %s across the licence boundary", name, p)
			}
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, bad := range []string{"docker.sock", "podman.sock", "http.MethodPost", "http.MethodPut", "http.MethodDelete", "sh -c", `"sh"`, `"bash"`, "os.Environ"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

func TestTTYContainerUsesRawStream(t *testing.T) {
	f := newFakeSockguard(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(stamp + "tty line\n"))
	})
	f.tty = true
	m := New(Config{SockguardSocket: f.sock, FlushInterval: 5 * time.Millisecond})
	m.Open(t.Context(), open("s1", "c1"))
	lines := next(t, m).GetLogChunk().GetLines()
	if len(lines) != 1 || string(lines[0].GetText()) != "tty line" {
		t.Fatalf("lines = %v", lines)
	}
}

func TestMissingContainerEndsWithCode(t *testing.T) {
	f := newFakeSockguard(t, nil)
	m := New(Config{SockguardSocket: f.sock})
	m.Open(t.Context(), open("s1", "ghost"))
	m2 := New(Config{SockguardSocket: filepath.Join(t.TempDir(), "none.sock")})
	m2.Open(t.Context(), open("s2", "ghost"))
	for _, mm := range []*Manager{m2} {
		if got := next(t, mm).GetLogEnded().GetCode(); got != string(errcode.LOGSrc001) {
			t.Errorf("code = %q, want %s", got, errcode.LOGSrc001)
		}
	}
	if got := next(t, m).GetLogEnded().GetCode(); got != string(errcode.LOGSrc001) {
		t.Errorf("code = %q, want %s", got, errcode.LOGSrc001)
	}
}

func TestBadRequestsAreRefusedBeforeAnySourceStarts(t *testing.T) {
	m := New(Config{SockguardSocket: filepath.Join(t.TempDir(), "none.sock"), JournalctlPath: "/nonexistent/journalctl"})
	reqs := []*agentv1.OpenLogStream{
		open("s1", "../etc"),
		open("s2", "a/b"),
		{StreamId: "s3", Source: &agentv1.OpenLogStream_JournalUnit{JournalUnit: "-f"}},
		{StreamId: "s4", Source: &agentv1.OpenLogStream_JournalUnit{JournalUnit: "x; id"}},
		{StreamId: "s5"},
	}
	for _, r := range reqs {
		m.Open(t.Context(), r)
		e := next(t, m).GetLogEnded()
		wantCode := string(errcode.LOGStr002)
		if r.GetStreamId() == "s5" {
			wantCode = string(errcode.LOGSrc001)
		}
		if e.GetStreamId() != r.GetStreamId() || e.GetCode() != wantCode {
			t.Errorf("%s: ended = %v, want code %s", r.GetStreamId(), e, wantCode)
		}
	}
}

func TestStreamCapPerAgent(t *testing.T) {
	f := newFakeSockguard(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	m := New(Config{SockguardSocket: f.sock, MaxStreams: 2})
	defer m.CloseAll()
	for i := range 2 {
		m.Open(t.Context(), open("s"+strconv.Itoa(i), "c"))
	}
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.requests) >= 4 })
	m.Open(t.Context(), open("s9", "c"))
	if e := next(t, m).GetLogEnded(); e.GetStreamId() != "s9" || e.GetCode() != string(errcode.LOGStr001) {
		t.Fatalf("ended = %v", e)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBackpressureStopsReadingTheSource(t *testing.T) {
	var written sync.Mutex
	count := 0
	f := newFakeSockguard(t, func(w http.ResponseWriter, r *http.Request) {
		payload := frame(1, stamp+strings.Repeat("z", 200)+"\n")
		for r.Context().Err() == nil {
			if _, err := w.Write(payload); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			written.Lock()
			count++
			written.Unlock()
		}
	})
	m := New(Config{SockguardSocket: f.sock, FlushInterval: 5 * time.Millisecond})
	m.Open(t.Context(), open("s1", "c"))
	time.Sleep(500 * time.Millisecond) // nobody reads Out: the link is "pushing back"

	read := func() int { written.Lock(); defer written.Unlock(); return count }
	a := read()
	time.Sleep(300 * time.Millisecond)
	b := read()
	// Socket and HTTP buffers absorb a bounded amount; after that the writer must block.
	if b != a || a > 20000 {
		t.Fatalf("source kept flowing: %d then %d frames written while nothing consumed", a, b)
	}
	m.CloseAll()
}

func TestCloseStopsTheStream(t *testing.T) {
	done := make(chan struct{})
	f := newFakeSockguard(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(done)
	})
	m := New(Config{SockguardSocket: f.sock})
	m.Open(t.Context(), open("s1", "c"))
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.requests) >= 2 })
	m.Close("s1")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the source request was not cancelled")
	}
	m.CloseAll()
	select {
	case msg := <-m.Out():
		t.Fatalf("unexpected message after close: %v", msg)
	default:
	}
}

// fakeJournalctl writes a script that records its pid and arguments, prints three entries
// and then waits, like journalctl --follow.
func fakeJournalctl(t *testing.T) (script, pidFile, argFile string) {
	t.Helper()
	dir := t.TempDir()
	script, pidFile, argFile = filepath.Join(dir, "journalctl"), filepath.Join(dir, "pid"), filepath.Join(dir, "args")
	body := `#!/bin/sh
echo $$ > "` + pidFile + `"
printf '%s\n' "$@" > "` + argFile + `"
env > "` + dir + `/env"
echo '{"MESSAGE":"started","__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6"}'
echo '{"MESSAGE":[104,105],"__REALTIME_TIMESTAMP":"1700000001000000"}'
echo 'not json'
exec sleep 60
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test helper script
		t.Fatal(err)
	}
	return script, pidFile, argFile
}

func TestJournalStreamAndKillOnClose(t *testing.T) { // LOG-2
	script, pidFile, argFile := fakeJournalctl(t)
	t.Setenv("NUX_SECRET_TEST", "leak-me")
	m := New(Config{JournalctlPath: script, FlushInterval: 5 * time.Millisecond})
	m.Open(t.Context(), &agentv1.OpenLogStream{StreamId: "j1", TailLines: 20, Source: &agentv1.OpenLogStream_JournalUnit{JournalUnit: "nginx.service"}})

	var texts []string
	for len(texts) < 3 {
		for _, l := range next(t, m).GetLogChunk().GetLines() {
			if l.GetSource() != agentv1.LogLine_SOURCE_JOURNAL {
				t.Errorf("source = %v", l.GetSource())
			}
			texts = append(texts, string(l.GetText()))
		}
	}
	if texts[0] != "started" || texts[1] != "hi" || texts[2] != "[unreadable journal entry]" {
		t.Errorf("texts = %q", texts)
	}
	args, _ := os.ReadFile(argFile) //nolint:gosec // test file
	if !strings.Contains(string(args), "--unit=nginx.service\n--lines=20") {
		t.Errorf("args = %q", args)
	}
	env, _ := os.ReadFile(filepath.Join(filepath.Dir(pidFile), "env")) //nolint:gosec // test file
	if strings.Contains(string(env), "leak-me") || strings.Contains(string(env), "NUX_SECRET_TEST") {
		t.Errorf("journalctl inherited the agent's environment: %q", env)
	}

	raw, _ := os.ReadFile(pidFile) //nolint:gosec // test file
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	m.Close("j1")
	m.CloseAll()
	waitFor(t, func() bool { return syscall.Kill(pid, 0) != nil })
}

func TestJournalctlMissingEndsWithCode(t *testing.T) {
	m := New(Config{JournalctlPath: "/nonexistent/journalctl"})
	m.Open(t.Context(), &agentv1.OpenLogStream{StreamId: "j1", Source: &agentv1.OpenLogStream_JournalUnit{JournalUnit: "nginx"}})
	if got := next(t, m).GetLogEnded().GetCode(); got != string(errcode.LOGSrc002) {
		t.Errorf("code = %q, want %s", got, errcode.LOGSrc002)
	}
}
