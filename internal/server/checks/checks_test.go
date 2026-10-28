// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

var bg = context.Background()

func mustValidation(t *testing.T, err error, field string) {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want a ValidationError on %s", err, field)
	}
	if ve.Field != field {
		t.Fatalf("field = %q, want %q (%s)", ve.Field, field, ve.Msg)
	}
}

func TestUPT3_IntervalTimeoutAndRetryBounds(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name  string
		edit  func(*Check)
		field string // empty: accepted
	}{
		{"interval 19", func(c *Check) { c.IntervalS = 19 }, "interval_s"},
		{"interval 20", func(c *Check) { c.IntervalS = 20; c.TimeoutS = 5 }, ""},
		{"interval 86400", func(c *Check) { c.IntervalS = 86400 }, ""},
		{"interval 86401", func(c *Check) { c.IntervalS = 86401 }, "interval_s"},
		{"timeout equals interval", func(c *Check) { c.TimeoutS = 60 }, "timeout_s"},
		{"timeout 61", func(c *Check) { c.IntervalS = 300; c.TimeoutS = 61 }, "timeout_s"},
		{"retries 5", func(c *Check) { c.Retries = 5 }, ""},
		{"retries 6", func(c *Check) { c.Retries = 6 }, "retries"},
		{"retries -1", func(c *Check) { c.Retries = -1 }, "retries"},
		{"default timeout", func(c *Check) { c.TimeoutS = 0 }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tcpCheck(tc.name)
			tc.edit(&c)
			_, err := e.svc.Create(bg, c, who)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			mustValidation(t, err, tc.field)
		})
	}
}

func TestUPT3_JitterSpreadsFirstRuns(t *testing.T) {
	buckets := map[time.Duration]bool{}
	for i := range 200 {
		id := fmt.Sprintf("01CHECK%019d", i)
		off := Offset(id, 60*time.Second)
		if off < 0 || off >= maxJitter {
			t.Fatalf("offset %v outside [0, %v)", off, maxJitter)
		}
		buckets[off.Truncate(time.Second)] = true
		if Offset(id, 60*time.Second) != off {
			t.Fatal("offset is not stable for one check")
		}
	}
	if len(buckets) < 20 {
		t.Fatalf("200 checks landed in only %d one-second slots; they would run in lockstep", len(buckets))
	}
	if off := Offset("01X", 20*time.Second); off >= 20*time.Second {
		t.Fatalf("offset %v is not below the interval", off)
	}
}

func TestUPT3_SchedulerRunsEachCheckOncePerInterval(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("db"))
	off := Offset(v.ID, time.Minute)
	if off > 0 {
		e.svc.Tick(bg)
		if e.exec.calls() != 0 {
			t.Fatal("check ran before its jitter offset")
		}
	}
	e.clock.Advance(off)
	e.svc.Tick(bg)
	e.svc.Tick(bg)
	if e.exec.calls() != 1 {
		t.Fatalf("calls = %d, want 1 after the offset", e.exec.calls())
	}
	e.clock.Advance(59 * time.Second)
	e.svc.Tick(bg)
	if e.exec.calls() != 1 {
		t.Fatal("ran again before the interval elapsed")
	}
	e.clock.Advance(time.Second)
	e.svc.Tick(bg)
	if e.exec.calls() != 2 {
		t.Fatalf("calls = %d, want 2 after one interval", e.exec.calls())
	}
	got := e.exec.specs[0]
	if got.Timeout != 5*time.Second || got.Type != probe.TypeTCP || got.TCP.Host != "db.example.com" {
		t.Fatalf("probe got %+v", got)
	}
}

func TestUPT3_EnableDisable(t *testing.T) {
	e := newEnv(t)
	c := tcpCheck("off")
	c.Enabled = false
	v := e.create(c)
	e.clock.Advance(time.Hour)
	e.svc.Tick(bg)
	if e.exec.calls() != 0 {
		t.Fatal("a disabled check ran")
	}
	c.Enabled = true
	v, err := e.svc.Update(bg, v.ID, v.ETag(), c, who)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	e.svc.Tick(bg)
	if e.exec.calls() != 1 {
		t.Fatalf("calls = %d after enabling", e.exec.calls())
	}
	c.Enabled = false
	if _, err := e.svc.Update(bg, v.ID, v.ETag(), c, who); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Hour)
	e.svc.Tick(bg)
	if e.exec.calls() != 1 {
		t.Fatal("a check ran after being disabled")
	}
}

func TestUPT3_RetriesBeforeMarkingDown(t *testing.T) {
	e := newEnv(t)
	e.exec.answers = []probe.Result{downResult, downResult, upResult}
	c := tcpCheck("flaky")
	c.Retries = 2
	v := e.create(c)
	e.clock.Advance(Offset(v.ID, time.Minute))
	e.svc.Tick(bg)
	if e.exec.calls() != 3 {
		t.Fatalf("attempts = %d, want 3", e.exec.calls())
	}
	if len(e.clock.slept) != 2 || e.clock.slept[0] != DefaultRetryDelay {
		t.Fatalf("retry delays = %v", e.clock.slept)
	}
	got, _ := e.svc.Get(bg, v.ID)
	if got.Status.State != StateUp || e.count(`SELECT count(*) FROM check_results WHERE status = 'down'`) != 0 {
		t.Fatalf("a recovered retry must not leave a down result: %+v", got.Status)
	}
}

func TestUPT3_DownOnlyAfterAllRetriesFail(t *testing.T) {
	e := newEnv(t)
	e.exec.answers = []probe.Result{downResult}
	c := tcpCheck("dead")
	c.Retries = 3
	v := e.create(c)
	e.clock.Advance(Offset(v.ID, time.Minute))
	e.svc.Tick(bg)
	if e.exec.calls() != 4 {
		t.Fatalf("attempts = %d, want 1 + 3 retries", e.exec.calls())
	}
	got, _ := e.svc.Get(bg, v.ID)
	if got.Status.State != StateDown || got.Status.LastErrorCode != "CHK-HTTP-002" || got.Status.LastDetail != "status 503" {
		t.Fatalf("status = %+v", got.Status)
	}
	if got.Status.LastLatencyMS == nil || *got.Status.LastLatencyMS != 3 || got.Status.LastChecked == nil {
		t.Fatalf("latency/last_checked missing: %+v", got.Status)
	}
	if e.count(`SELECT count(*) FROM check_results WHERE check_id = ?`, v.ID) != 1 {
		t.Fatal("one scheduled run must record exactly one result")
	}
}

func TestUPT3_StateTransitionsPublishEvents(t *testing.T) {
	e := newEnv(t)
	sub := e.svc.Hub().Subscribe()
	defer sub.Close()
	v := e.create(tcpCheck("svc"))
	run := func(r probe.Result) {
		e.exec.mu.Lock()
		e.exec.answers = []probe.Result{r}
		e.exec.mu.Unlock()
		e.clock.Advance(ManualRunGap)
		if _, err := e.svc.RunNow(bg, v.ID, who); err != nil {
			t.Fatal(err)
		}
	}
	run(upResult)
	run(upResult) // no change, no event
	run(downResult)
	run(downResult)
	run(upResult)
	var got []string
	for len(sub.C) > 0 {
		ev := <-sub.C
		got = append(got, ev.From+">"+ev.To)
		if ev.CheckID != v.ID || ev.Name != "svc" {
			t.Fatalf("event = %+v", ev)
		}
	}
	if strings.Join(got, ",") != "unknown>up,up>down,down>up" {
		t.Fatalf("events = %v", got)
	}
}

func TestUPT3_HubClosesLaggingSubscribers(t *testing.T) {
	h := NewHub()
	slow := h.Subscribe()
	fast := h.Subscribe()
	for i := range subscriberBuffer + 1 {
		h.Publish(Event{CheckID: fmt.Sprint(i)})
		for len(fast.C) > 0 {
			<-fast.C
		}
	}
	n := 0
	for range slow.C {
		n++
	}
	if n != subscriberBuffer || !slow.Lagged() {
		t.Fatalf("slow got %d events, lagged = %v", n, slow.Lagged())
	}
	if fast.Lagged() {
		t.Fatal("a keeping-up subscriber was dropped")
	}
	fast.Close()
	fast.Close() // idempotent
}

func TestUPT3_ConcurrencyIsBounded(t *testing.T) {
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var cur, peak atomic.Int32
	e := newEnv(t, func(o *Options) {
		o.Inline = false
		o.MaxConcurrent = 2
		o.Exec = func(ctx context.Context, _ probe.Policy, _ probe.Spec) probe.Result {
			n := cur.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			cur.Add(-1)
			return upResult
		}
	})
	for i := range 5 {
		e.create(tcpCheck(fmt.Sprint("c", i)))
	}
	e.clock.Advance(time.Minute)
	e.svc.Tick(bg)
	<-started
	<-started
	e.svc.Tick(bg) // the other three are due but no worker is free
	e.svc.mu.Lock()
	running := len(e.svc.running)
	e.svc.mu.Unlock()
	if running != 2 || peak.Load() != 2 {
		t.Fatalf("running = %d, peak = %d, want 2", running, peak.Load())
	}
	close(release)
	e.svc.wg.Wait()
	for range 5 { // the three that waited start as workers free up
		e.svc.Tick(bg)
		e.svc.wg.Wait()
	}
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency %d exceeded the limit", peak.Load())
	}
	if n := e.count(`SELECT count(DISTINCT check_id) FROM check_results`); n != 5 {
		t.Fatalf("%d of 5 checks eventually ran", n)
	}
}

func TestUPT3_GracefulStopCancelsAndWaits(t *testing.T) {
	started := make(chan struct{})
	e := newEnv(t, func(o *Options) {
		o.Inline = false
		o.Exec = func(ctx context.Context, _ probe.Policy, _ probe.Spec) probe.Result {
			close(started)
			<-ctx.Done()
			return downResult
		}
	})
	e.create(tcpCheck("slow"))
	ctx, cancel := context.WithCancel(bg)
	e.clock.Advance(time.Minute)
	e.svc.Tick(ctx)
	<-started
	done := make(chan struct{})
	go func() { e.svc.wg.Wait(); close(done) }()
	cancel()
	<-done // returns only once the running check ended

	runDone := make(chan error)
	ctx2, cancel2 := context.WithCancel(bg)
	go func() { runDone <- e.svc.Run(ctx2) }()
	cancel2()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
}

func TestUPT3_TimeoutReachesTheProbe(t *testing.T) {
	e := newEnv(t)
	c := tcpCheck("t")
	c.TimeoutS = 7
	v := e.create(c)
	if _, err := e.svc.RunNow(bg, v.ID, who); err != nil {
		t.Fatal(err)
	}
	if got := e.exec.specs[0].Timeout; got != 7*time.Second {
		t.Fatalf("timeout = %v", got)
	}
}

func TestUPT3_RunNowIsRateLimitedAndAudited(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("r"))
	if _, err := e.svc.RunNow(bg, v.ID, who); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RunNow(bg, v.ID, who); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second immediate run = %v, want ErrRateLimited", err)
	}
	e.clock.Advance(ManualRunGap)
	if _, err := e.svc.RunNow(bg, v.ID, who); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'check.run' AND target_id = ?`, v.ID); n != 2 {
		t.Fatalf("check.run audit entries = %d, want 2", n)
	}
	if _, err := e.svc.RunNow(bg, "01NOSUCHCHECK000000000000", who); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown check = %v", err)
	}
}

func TestUPT5_SecretsAreWriteOnlyEncryptedAndNeverLogged(t *testing.T) {
	e := newEnv(t)
	c := httpCheck("https://api.example.com/health")
	c.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("tok-PLAINTEXT-1")}}
	c.HTTP.Headers = []Header{{Name: "X-Api-Key", Secret: true, Set: &Secret{Plain: ptr("key-PLAINTEXT-2")}}, {Name: "X-Env", Value: "prod"}}
	v := e.create(c)

	if !v.HTTP.Auth.Token.IsSet || !v.HTTP.Headers[0].Set.IsSet {
		t.Fatalf("secrets not reported as set: %+v", v.HTTP)
	}
	if _, err := e.svc.RunNow(bg, v.ID, who); err != nil {
		t.Fatal(err)
	}
	h := e.exec.specs[0].HTTP.Headers
	if h["Authorization"] != "Bearer tok-PLAINTEXT-1" || h["X-Api-Key"] != "key-PLAINTEXT-2" || h["X-Env"] != "prod" {
		t.Fatalf("resolved headers = %v", h)
	}

	// Keep: an echoed GET document (secret as {"set":true}) changes nothing.
	got, _ := e.svc.Get(bg, v.ID)
	keep := got.Check
	keep.HTTP.Auth.Token = &Secret{} // Plain == nil
	keep.HTTP.Headers[0].Set = &Secret{}
	v2, err := e.svc.Update(bg, v.ID, got.ETag(), keep, who)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.HTTP.Auth.Token.IsSet {
		t.Fatal("keep lost the token")
	}
	e.clock.Advance(ManualRunGap)
	if _, err := e.svc.RunNow(bg, v.ID, who); err != nil {
		t.Fatal(err)
	}
	if e.exec.specs[1].HTTP.Headers["Authorization"] != "Bearer tok-PLAINTEXT-1" {
		t.Fatal("kept token no longer resolves")
	}

	// Replace.
	rep := v2.Check
	rep.HTTP.Auth.Token = &Secret{Plain: ptr("tok-PLAINTEXT-3")}
	rep.HTTP.Headers[0].Set = &Secret{}
	v3, err := e.svc.Update(bg, v.ID, v2.ETag(), rep, who)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(ManualRunGap)
	_, _ = e.svc.RunNow(bg, v.ID, who)
	if e.exec.specs[2].HTTP.Headers["Authorization"] != "Bearer tok-PLAINTEXT-3" {
		t.Fatal("replaced token not used")
	}
	if n := e.count(`SELECT count(*) FROM secrets`); n != 2 {
		t.Fatalf("secrets rows = %d, want 2 (replace reuses the row)", n)
	}

	// Clearing a required secret is refused and changes nothing.
	clr := v3.Check
	clr.HTTP.Auth.Token = &Secret{Plain: ptr("")}
	clr.HTTP.Headers[0].Set = &Secret{}
	_, err = e.svc.Update(bg, v.ID, v3.ETag(), clr, who)
	mustValidation(t, err, "http.auth.token")
	if n := e.count(`SELECT count(*) FROM secrets`); n != 2 {
		t.Fatalf("a refused update changed secrets: %d rows", n)
	}

	// Dropping auth and the secret header removes their secrets.
	drop := v3.Check
	drop.HTTP.Auth = &Auth{Type: "none"}
	drop.HTTP.Headers = []Header{{Name: "X-Env", Value: "prod"}}
	v4, err := e.svc.Update(bg, v.ID, v3.ETag(), drop, who)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM secrets`); n != 0 {
		t.Fatalf("secrets rows after dropping = %d", n)
	}

	// Stale ETag: nothing is written, including secrets.
	stale := v4.Check
	stale.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("tok-PLAINTEXT-4")}}
	if _, err := e.svc.Update(bg, v.ID, v3.ETag(), stale, who); !errors.Is(err, ErrStale) {
		t.Fatalf("stale update = %v", err)
	}
	if n := e.count(`SELECT count(*) FROM secrets`); n != 0 {
		t.Fatalf("a stale update stored %d secrets", n)
	}

	// Delete removes secrets too.
	bearer := v4.Check
	bearer.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("tok-PLAINTEXT-5")}}
	v5, err := e.svc.Update(bg, v.ID, v4.ETag(), bearer, who)
	if err != nil {
		t.Fatal(err)
	}
	dump := e.dump()
	for _, plain := range []string{"tok-PLAINTEXT-1", "key-PLAINTEXT-2", "tok-PLAINTEXT-3", "tok-PLAINTEXT-5"} {
		if strings.Contains(dump, plain) || strings.Contains(e.logs.String(), plain) {
			t.Errorf("plaintext %q found in the database or logs", plain)
		}
	}
	if err := e.svc.Delete(bg, v5.ID, who); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM secrets`); n != 0 {
		t.Fatalf("secrets rows after delete = %d", n)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'check.delete'`) != 1 || e.count(`SELECT count(*) FROM check_results`) != 0 {
		t.Fatal("delete must audit and cascade history")
	}
}

func TestUPT5_BasicAuthIsBase64OfUserAndPassword(t *testing.T) {
	e := newEnv(t)
	c := httpCheck("https://api.example.com/")
	c.HTTP.Auth = &Auth{Type: "basic", Username: "ada", Password: &Secret{Plain: ptr("p4ss")}}
	v := e.create(c)
	_, _ = e.svc.RunNow(bg, v.ID, who)
	if got := e.exec.specs[0].HTTP.Headers["Authorization"]; got != "Basic YWRhOnA0c3M=" {
		t.Fatalf("Authorization = %q", got)
	}
	if strings.Contains(e.dump(), "p4ss") {
		t.Fatal("password stored in plaintext")
	}
	nopw := httpCheck("https://api.example.com/")
	nopw.HTTP.Auth = &Auth{Type: "basic", Username: "ada"}
	_, err := e.svc.Create(bg, nopw, who)
	mustValidation(t, err, "http.auth.password")
}

func TestUPT5_AuditEntriesCarryNoCredentials(t *testing.T) {
	e := newEnv(t)
	c := httpCheck("https://api.example.com/")
	c.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("tok-AUDIT-SECRET")}}
	v := e.create(c)
	row := e.db.DB().QueryRow(`SELECT details_json FROM audit_log WHERE action = 'check.create' AND target_id = ?`, v.ID)
	var details string
	if err := row.Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "tok-AUDIT-SECRET") || !strings.Contains(details, "auth.token") {
		t.Fatalf("audit details = %s", details)
	}
}

func TestUPT5_ValidationNegatives(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("a", 2100)
	for _, tc := range []struct {
		name  string
		edit  func(*Check)
		field string
	}{
		{"CRLF in header value", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X-A", Value: "a\r\nX-B: c"}} }, "http.headers[0].value"},
		{"LF in header value", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X-A", Value: "a\nb"}} }, "http.headers[0].value"},
		{"CRLF in header name", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X-A\r\nX-B", Value: "a"}} }, "http.headers[0].name"},
		{"space in header name", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X A", Value: "a"}} }, "http.headers[0].name"},
		{"Host override", func(c *Check) { c.HTTP.Headers = []Header{{Name: "host", Value: "evil"}} }, "http.headers[0].name"},
		{"Transfer-Encoding", func(c *Check) { c.HTTP.Headers = []Header{{Name: "Transfer-Encoding", Value: "chunked"}} }, "http.headers[0].name"},
		{"Content-Length", func(c *Check) { c.HTTP.Headers = []Header{{Name: "Content-Length", Value: "0"}} }, "http.headers[0].name"},
		{"Connection", func(c *Check) { c.HTTP.Headers = []Header{{Name: "Connection", Value: "close"}} }, "http.headers[0].name"},
		{"Proxy-Authorization", func(c *Check) { c.HTTP.Headers = []Header{{Name: "Proxy-Authorization", Value: "x"}} }, "http.headers[0].name"},
		{"duplicate header", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X-A", Value: "1"}, {Name: "x-a", Value: "2"}} }, "http.headers[1].name"},
		{"too many headers", func(c *Check) {
			for i := range 21 {
				c.HTTP.Headers = append(c.HTTP.Headers, Header{Name: fmt.Sprint("X-H", i), Value: "v"})
			}
		}, "http.headers"},
		{"header value too long", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X-A", Value: strings.Repeat("v", 1025)}} }, "http.headers[0].value"},
		{"secret header with plain value", func(c *Check) { c.HTTP.Headers = []Header{{Name: "X-K", Secret: true, Value: "oops"}} }, "http.headers[0].value"},
		{"authorization with auth", func(c *Check) {
			c.HTTP.Headers = []Header{{Name: "Authorization", Value: "x"}}
			c.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("t")}}
		}, "http.headers[0].name"},
		{"userinfo URL", func(c *Check) { c.HTTP.URL = "https://user:pw@example.com/" }, "http.url"},
		{"user only URL", func(c *Check) { c.HTTP.URL = "https://user@example.com/" }, "http.url"},
		{"ftp scheme", func(c *Check) { c.HTTP.URL = "ftp://example.com/" }, "http.url"},
		{"file scheme", func(c *Check) { c.HTTP.URL = "file:///etc/passwd" }, "http.url"},
		{"javascript scheme", func(c *Check) { c.HTTP.URL = "javascript:alert(1)" }, "http.url"},
		{"no scheme", func(c *Check) { c.HTTP.URL = "example.com/x" }, "http.url"},
		{"URL with space", func(c *Check) { c.HTTP.URL = "https://example.com/a b" }, "http.url"},
		{"URL with CRLF", func(c *Check) { c.HTTP.URL = "https://example.com/\r\nHost: x" }, "http.url"},
		{"URL too long", func(c *Check) { c.HTTP.URL = "https://example.com/" + long }, "http.url"},
		{"bad port", func(c *Check) { c.HTTP.URL = "https://example.com:99999/" }, "http.url"},
		{"huge body", func(c *Check) { c.HTTP.Method = "POST"; c.HTTP.Body = strings.Repeat("b", 4097) }, "http.body"},
		{"body on GET", func(c *Check) { c.HTTP.Body = "x" }, "http.body"},
		{"bad method", func(c *Check) { c.HTTP.Method = "TRACE" }, "http.method"},
		{"bad status code", func(c *Check) { c.HTTP.ExpectedStatus = []int{99} }, "http.expected_status"},
		{"redirects 11", func(c *Check) { c.HTTP.MaxRedirects = ptr(11) }, "http.max_redirects"},
		{"body cap too big", func(c *Check) { c.HTTP.MaxBodyBytes = 2 << 20 }, "http.max_body_bytes"},
		{"bad JSON path", func(c *Check) { c.HTTP.JSON = &JSONMatch{Path: "a[", Op: "exists"} }, "http.json.path"},
		{"bad JSON op", func(c *Check) { c.HTTP.JSON = &JSONMatch{Path: "a", Op: "regex"} }, "http.json.op"},
		{"bad auth type", func(c *Check) { c.HTTP.Auth = &Auth{Type: "digest"} }, "http.auth.type"},
		{"basic username with colon", func(c *Check) {
			c.HTTP.Auth = &Auth{Type: "basic", Username: "a:b", Password: &Secret{Plain: ptr("x")}}
		}, "http.auth.username"},
		{"token with space", func(c *Check) { c.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("a b")}} }, "http.auth.token"},
		{"loopback literal", func(c *Check) { c.HTTP.URL = "http://127.0.0.1/" }, "http.url"},
		{"metadata literal", func(c *Check) { c.HTTP.URL = "http://169.254.169.254/latest" }, "http.url"},
		{"IPv6 loopback literal", func(c *Check) { c.HTTP.URL = "http://[::1]/" }, "http.url"},
		{"mapped IPv6 loopback", func(c *Check) { c.HTTP.URL = "http://[::ffff:127.0.0.1]/" }, "http.url"},
		{"private literal without allow_private", func(c *Check) { c.HTTP.URL = "http://10.0.0.5/" }, "http.url"},
		{"unknown runner", func(c *Check) { c.Runner = "somebody" }, "runner"},
		{"empty name", func(c *Check) { c.Name = "  " }, "name"},
		{"control char in name", func(c *Check) { c.Name = "a\x00b" }, "name"},
		{"unknown type", func(c *Check) { c.Type = "grpc" }, "type"},
		{"missing section", func(c *Check) { c.HTTP = nil }, "http"},
		{"extra section", func(c *Check) { c.TCP = &TCPConfig{Host: "a", Port: 1} }, "tcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := httpCheck("https://example.com/")
			tc.edit(&c)
			_, err := e.svc.Create(bg, c, who)
			mustValidation(t, err, tc.field)
		})
	}
	if e.count(`SELECT count(*) FROM checks`) != 0 || e.count(`SELECT count(*) FROM secrets`) != 0 {
		t.Fatal("a refused check left rows behind")
	}
}

func TestUPT1_ValidationOfOtherTypes(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name  string
		c     Check
		field string
	}{
		{"tcp port 0", Check{Type: probe.TypeTCP, TCP: &TCPConfig{Host: "a.example.com", Port: 0}}, "tcp.port"},
		{"tcp port 65536", Check{Type: probe.TypeTCP, TCP: &TCPConfig{Host: "a.example.com", Port: 65536}}, "tcp.port"},
		{"tcp host with slash", Check{Type: probe.TypeTCP, TCP: &TCPConfig{Host: "/run/nux/sockguard.sock", Port: 80}}, "tcp.host"},
		{"tcp host with port", Check{Type: probe.TypeTCP, TCP: &TCPConfig{Host: "a.example.com:80", Port: 80}}, "tcp.host"},
		{"tcp loopback", Check{Type: probe.TypeTCP, TCP: &TCPConfig{Host: "127.0.0.1", Port: 80}}, "tcp.host"},
		{"dns bad type", Check{Type: probe.TypeDNS, DNS: &DNSConfig{Name: "a.example.com", RecordType: "SRV"}}, "dns.record_type"},
		{"dns bad resolver", Check{Type: probe.TypeDNS, DNS: &DNSConfig{Name: "a.example.com", RecordType: "A", Resolver: "9.9.9.9"}}, "dns.resolver"},
		{"dns loopback resolver", Check{Type: probe.TypeDNS, DNS: &DNSConfig{Name: "a.example.com", RecordType: "A", Resolver: "127.0.0.1:53"}}, "dns.resolver"},
		{"dns too many expected", Check{Type: probe.TypeDNS, DNS: &DNSConfig{Name: "a.example.com", RecordType: "A", Expected: make([]string, 11)}}, "dns.expected"},
		{"tls warn days", Check{Type: probe.TypeTLS, TLS: &TLSConfig{Host: "a.example.com", WarnDays: ptr(366)}}, "tls.warn_days"},
		{"tls bad server name", Check{Type: probe.TypeTLS, TLS: &TLSConfig{Host: "a.example.com", ServerName: "a b"}}, "tls.server_name"},
		{"ping count", Check{Type: probe.TypePing, Ping: &PingConfig{Host: "a.example.com", Count: 6}}, "ping.count"},
		{"ping metadata", Check{Type: probe.TypePing, Ping: &PingConfig{Host: "169.254.169.254"}}, "ping.host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			c.Name, c.IntervalS, c.TimeoutS = "x", 60, 5
			_, err := e.svc.Create(bg, c, who)
			mustValidation(t, err, tc.field)
		})
	}
	// Defaults are applied and accepted.
	v := e.create(Check{Name: "cert", Type: probe.TypeTLS, IntervalS: 3600, Enabled: true, TLS: &TLSConfig{Host: "example.com"}})
	if v.TLS.Port != 443 || *v.TLS.WarnDays != 14 || !*v.TLS.VerifyChain || v.TimeoutS != 10 {
		t.Fatalf("defaults = %+v timeout %d", v.TLS, v.TimeoutS)
	}
	d := e.create(Check{Name: "dns", Type: probe.TypeDNS, IntervalS: 60, DNS: &DNSConfig{Name: "example.com", RecordType: "mx"}})
	if d.DNS.RecordType != "MX" {
		t.Fatal("record type not normalised")
	}
}

func TestT11_AllowPrivateAndTheServerHardBlock(t *testing.T) {
	e := newEnv(t)
	c := httpCheck("http://10.0.0.5/")
	_, err := e.svc.Create(bg, c, who)
	mustValidation(t, err, "http.url")
	c.AllowPrivate = true
	v, err := e.svc.Create(bg, c, who)
	if err != nil {
		t.Fatalf("allow_private check refused: %v", err)
	}
	// It reaches the probe with a policy that admits private ranges but nothing else.
	_, _ = e.svc.RunNow(bg, v.ID, who)
	if p := e.exec.policy[0]; !p.AllowPrivate || p.AllowLoopback {
		t.Fatalf("policy = %+v", p)
	}
	// Loopback and metadata stay refused even with allow_private.
	for _, u := range []string{"http://127.0.0.1/", "http://169.254.169.254/"} {
		c := httpCheck(u)
		c.AllowPrivate = true
		_, err := e.svc.Create(bg, c, who)
		mustValidation(t, err, "http.url")
	}

	hard := newEnv(t, func(o *Options) { o.BlockPrivate = true })
	_, err = hard.svc.Create(bg, c, who)
	mustValidation(t, err, "allow_private")
	// And a stored allow_private check is not honoured when the admin blocks private ranges.
	if p := (probe.Policy{AllowPrivate: true && !hard.svc.BlockPrivate}); p.AllowPrivate {
		t.Fatal("hard block ignored")
	}
}

func TestT11_ServerRunCheckIsGuardedEndToEnd(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Exec = nil })
	// "localhost" is a valid name at save time; the guard catches where it resolves at connect time.
	v := e.create(Check{Name: "sneaky", Type: probe.TypeTCP, IntervalS: 60, TimeoutS: 2, Enabled: true, TCP: &TCPConfig{Host: "localhost", Port: 9}})
	res, err := e.svc.RunNow(bg, v.ID, who)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StateDown || res.ErrorCode != string(errcode.CHKNet001) {
		t.Fatalf("result = %+v, want down CHK-NET-001", res)
	}
}

func TestUPT1_ServiceRunsRealProbeWithResolvedCredentials(t *testing.T) {
	var sawAuth atomic.Value
	srv := newLocalServer(func(h map[string]string) { sawAuth.Store(h["Authorization"]) })
	defer srv.Close()
	e := newEnv(t, func(o *Options) {
		o.Exec = nil
		o.Policy = func(Check) probe.Policy { return probe.AgentPolicy() } // the test server is on loopback
	})
	c := httpCheck(srv.URL + "/")
	c.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("real-token")}}
	c.HTTP.ExpectedStatus = []int{200}
	c.HTTP.Keyword = "welcome"
	// Loopback literal is refused at save time; the policy override only affects execution, so use a name.
	c.HTTP.URL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/"
	v := e.create(c)
	res, err := e.svc.RunNow(bg, v.ID, who)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StateUp {
		t.Fatalf("result = %+v", res)
	}
	if sawAuth.Load() != "Bearer real-token" {
		t.Fatalf("server saw %v", sawAuth.Load())
	}
}

// ---- agent-run checks (NUX-28) ----

func agentID(c byte) string { return "01AGENT" + strings.Repeat(string(c), 19) }

func agentEnv(t *testing.T, mut ...func(*Options)) (*env, string, View) {
	t.Helper()
	e := newEnv(t, mut...)
	a := agentID('A')
	e.agents.agents[a] = gateway.AgentInfo{ID: a}
	e.agents.agents[agentID('B')] = gateway.AgentInfo{ID: agentID('B')}
	e.agents.agents[agentID('R')] = gateway.AgentInfo{ID: agentID('R'), Revoked: true}
	c := httpCheck("http://10.1.2.3/health") // private target: fine for an agent
	c.Runner = a
	c.HTTP.Auth = &Auth{Type: "bearer", Token: &Secret{Plain: ptr("agent-secret-token")}}
	return e, a, e.create(c)
}

type runOutcome struct {
	res Result
	err error
}

func runAsync(e *env, id string) <-chan runOutcome {
	ch := make(chan runOutcome, 1)
	go func() {
		r, err := e.svc.RunNow(bg, id, who)
		ch <- runOutcome{r, err}
	}()
	return ch
}

func resultMsg(runID, checkID string, st agentv1.CheckResult_Status, code string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_CheckResult{CheckResult: &agentv1.CheckResult{
		CheckId: checkID, RunId: runID, Status: st, LatencyMs: 42, ErrorCode: code, Detail: "days_remaining=9\n",
	}}}
}

func TestUPT2_AgentRunCheckRoundTrip(t *testing.T) {
	e, a, v := agentEnv(t)
	done := runAsync(e, v.ID)
	sent := <-e.sender.sent
	if sent.agentID != a || sent.run.GetCheckId() != v.ID || sent.run.GetRunId() == "" || sent.run.GetTimeoutMs() != 5000 {
		t.Fatalf("sent %+v", sent)
	}
	if got := sent.run.GetHttp().GetHeaders()["Authorization"]; got != "Bearer agent-secret-token" {
		t.Fatalf("secret not resolved into the request: %q", got)
	}
	if e.svc.PendingCount() != 1 {
		t.Fatal("request not pending")
	}
	e.svc.HandleMessage(a, resultMsg(sent.run.GetRunId(), v.ID, agentv1.CheckResult_STATUS_UP, ""))
	out := <-done
	if out.err != nil || out.res.Status != StateUp || out.res.LatencyMS != 42 || out.res.Detail != "days_remaining=9" {
		t.Fatalf("outcome = %+v", out)
	}
	got, _ := e.svc.Get(bg, v.ID)
	if got.Status.State != StateUp || e.svc.PendingCount() != 0 {
		t.Fatalf("status %+v pending %d", got.Status, e.svc.PendingCount())
	}
	for _, sink := range []string{e.logs.String(), e.dump()} {
		if strings.Contains(sink, "agent-secret-token") {
			t.Fatal("secret leaked into logs or the database")
		}
	}
}

func TestUPT2_AgentReportsDownWithCode(t *testing.T) {
	e, a, v := agentEnv(t)
	done := runAsync(e, v.ID)
	sent := <-e.sender.sent
	e.svc.HandleMessage(a, resultMsg(sent.run.GetRunId(), v.ID, agentv1.CheckResult_STATUS_DOWN, "CHK-HTTP-001"))
	if out := <-done; out.res.Status != StateDown || out.res.ErrorCode != "CHK-HTTP-001" {
		t.Fatalf("outcome = %+v", out)
	}
	// A garbage error code from an agent cannot inject text into our records.
	e.clock.Advance(ManualRunGap)
	done = runAsync(e, v.ID)
	sent = <-e.sender.sent
	e.svc.HandleMessage(a, resultMsg(sent.run.GetRunId(), v.ID, agentv1.CheckResult_STATUS_DOWN, "<script>alert(1)</script>"))
	if out := <-done; out.res.ErrorCode != string(errcode.CHKRun003) {
		t.Fatalf("unsanitised code accepted: %+v", out.res)
	}
}

func TestUPT2_ResultsFromTheWrongAgentOrForTheWrongCheckAreIgnored(t *testing.T) {
	e, a, v := agentEnv(t)
	other := e.create(tcpCheck("other"))
	done := runAsync(e, v.ID)
	sent := <-e.sender.sent
	runID := sent.run.GetRunId()

	e.svc.HandleMessage(agentID('B'), resultMsg(runID, v.ID, agentv1.CheckResult_STATUS_UP, "")) // another agent
	e.svc.HandleMessage(a, resultMsg(runID, other.ID, agentv1.CheckResult_STATUS_UP, ""))        // another check
	e.svc.HandleMessage(a, resultMsg("01UNKNOWNRUN0000000000000", v.ID, agentv1.CheckResult_STATUS_UP, ""))
	e.svc.HandleMessage(a, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{}}})
	if e.svc.Ignored() != 3 || e.svc.PendingCount() != 1 {
		t.Fatalf("ignored = %d pending = %d", e.svc.Ignored(), e.svc.PendingCount())
	}
	select {
	case out := <-done:
		t.Fatalf("a forged result completed the run: %+v", out)
	default:
	}
	if e.count(`SELECT count(*) FROM check_results`) != 0 {
		t.Fatal("a forged result was recorded")
	}

	e.svc.HandleMessage(a, resultMsg(runID, v.ID, agentv1.CheckResult_STATUS_UP, ""))
	if out := <-done; out.res.Status != StateUp {
		t.Fatalf("genuine result = %+v", out)
	}
	e.svc.HandleMessage(a, resultMsg(runID, v.ID, agentv1.CheckResult_STATUS_DOWN, "CHK-HTTP-001")) // duplicate
	if e.svc.Ignored() != 4 || e.count(`SELECT count(*) FROM check_results`) != 1 {
		t.Fatalf("duplicate was not ignored: ignored = %d", e.svc.Ignored())
	}
}

func TestUPT2_LateResultAfterExpiryIsIgnored(t *testing.T) {
	e, a, v := agentEnv(t)
	done := runAsync(e, v.ID)
	sent := <-e.sender.sent
	e.clock.Advance(5*time.Second + pendingGrace + time.Second)
	e.svc.Tick(bg)
	out := <-done
	if out.res.Status != StateUnknown || out.res.ErrorCode != string(errcode.CHKRun003) {
		t.Fatalf("expired request = %+v", out.res)
	}
	e.svc.HandleMessage(a, resultMsg(sent.run.GetRunId(), v.ID, agentv1.CheckResult_STATUS_UP, ""))
	if e.svc.Ignored() != 1 || e.svc.PendingCount() != 0 {
		t.Fatalf("late result not ignored: ignored = %d", e.svc.Ignored())
	}
}

func TestUPT2_OfflineAndBusyAgentsGiveUnknownNotDown(t *testing.T) {
	e, _, v := agentEnv(t)
	for _, tc := range []struct {
		err  error
		code errcode.Code
	}{{gateway.ErrAgentOffline, errcode.CHKRun001}, {gateway.ErrAgentBusy, errcode.CHKRun002}} {
		e.sender.fail(tc.err)
		e.clock.Advance(ManualRunGap)
		res, err := e.svc.RunNow(bg, v.ID, who)
		if err != nil || res.Status != StateUnknown || res.ErrorCode != string(tc.code) {
			t.Fatalf("%v -> %+v, %v", tc.err, res, err)
		}
	}
	got, _ := e.svc.Get(bg, v.ID)
	if got.Status.State != StateUnknown || e.count(`SELECT count(*) FROM check_results WHERE status = 'down'`) != 0 {
		t.Fatalf("offline agent must not make the check down: %+v", got.Status)
	}
	if e.svc.PendingCount() != 0 || len(e.clock.slept) != 0 {
		t.Fatal("a failed send left a pending request or retried")
	}
}

func TestUPT2_AgentGoneResolvesPendingAsUnknown(t *testing.T) {
	e, a, v := agentEnv(t)
	done := runAsync(e, v.ID)
	<-e.sender.sent
	e.svc.AgentGone(a)
	if out := <-done; out.res.Status != StateUnknown || out.res.ErrorCode != string(errcode.CHKRun001) {
		t.Fatalf("outcome = %+v", out.res)
	}
}

func TestUPT2_AgentRefusalIsUnknown(t *testing.T) {
	e, a, v := agentEnv(t)
	done := runAsync(e, v.ID)
	sent := <-e.sender.sent
	e.svc.HandleMessage(a, resultMsg(sent.run.GetRunId(), v.ID, agentv1.CheckResult_STATUS_UNSPECIFIED, "CHK-RUN-002"))
	if out := <-done; out.res.Status != StateUnknown || out.res.ErrorCode != "CHK-RUN-002" {
		t.Fatalf("outcome = %+v", out.res)
	}
}

func TestUPT2_RunnerMustBeAnExistingUnrevokedAgent(t *testing.T) {
	e, _, _ := agentEnv(t)
	for name, runner := range map[string]string{"unknown": agentID('Z'), "revoked": agentID('R')} {
		c := tcpCheck(name)
		c.Runner = runner
		_, err := e.svc.Create(bg, c, who)
		mustValidation(t, err, "runner")
	}
	c := tcpCheck("loopback on an agent")
	c.Runner = agentID('B')
	c.TCP.Host = "127.0.0.1" // agents sit inside the target network, so no server-side block
	if _, err := e.svc.Create(bg, c, who); err != nil {
		t.Fatalf("agent-run loopback check refused: %v", err)
	}
	// Moving a check between runners is an ordinary update.
	srv := e.create(tcpCheck("movable"))
	moved := srv.Check
	moved.Runner = agentID('B')
	if _, err := e.svc.Update(bg, srv.ID, srv.ETag(), moved, who); err != nil {
		t.Fatal(err)
	}
}

func TestUPT2_ScheduledAgentCheckSendsOverTheStream(t *testing.T) {
	e, a, v := agentEnv(t, func(o *Options) { o.Inline = false })
	e.clock.Advance(Offset(v.ID, time.Minute))
	e.svc.Tick(bg)
	sent := <-e.sender.sent
	if sent.agentID != a {
		t.Fatalf("sent to %s", sent.agentID)
	}
	e.svc.HandleMessage(a, resultMsg(sent.run.GetRunId(), v.ID, agentv1.CheckResult_STATUS_UP, ""))
	e.svc.wg.Wait()
	if got, _ := e.svc.Get(bg, v.ID); got.Status.State != StateUp {
		t.Fatalf("status = %+v", got.Status)
	}
}

// ---- history, uptime, rollups ----

func record(t *testing.T, e *env, v View, status string, after time.Duration) {
	t.Helper()
	e.clock.Advance(after)
	if err := e.svc.record(bg, v.Check, outcome{status: status, latency: 10 * time.Millisecond}, nil); err != nil {
		t.Fatal(err)
	}
}

func near(t *testing.T, got *float64, want float64) {
	t.Helper()
	if got == nil || math.Abs(*got-want) > 0.0005 {
		var g any = "nil"
		if got != nil {
			g = *got
		}
		t.Fatalf("uptime = %v, want %v", g, want)
	}
}

func TestUPT4_UptimeArithmetic(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("u")) // 60 s per result
	u, _ := e.svc.Uptime(bg, v.ID)
	if u.H24 != nil || u.D90 != nil {
		t.Fatal("a check without results must have no uptime")
	}
	record(t, e, v, StateDown, 0)
	e.clock.Advance(48 * time.Hour)
	for range 3 {
		record(t, e, v, StateUp, time.Minute)
	}
	record(t, e, v, StateUnknown, time.Minute) // unknown counts for nothing
	u, err := e.svc.Uptime(bg, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	near(t, u.H24, 100)
	near(t, u.D7, 75)
	near(t, u.D30, 75)
	near(t, u.D90, 75)
	record(t, e, v, StateDown, time.Minute)
	u, _ = e.svc.Uptime(bg, v.ID)
	near(t, u.H24, 75)
	near(t, u.D7, 60)
}

func TestUPT4_ResultsArePaginatedNewestFirst(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("p"))
	for i := range 5 {
		st := StateUp
		if i == 3 {
			st = StateDown
		}
		record(t, e, v, st, time.Minute)
	}
	var all []Result
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		items, next, err := e.svc.Results(bg, v.ID, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, items...)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(all) != 5 || all[1].Status != StateDown {
		t.Fatalf("results = %+v", all)
	}
	for i := 1; i < len(all); i++ {
		if !all[i].TS.Before(all[i-1].TS) {
			t.Fatal("results are not newest first")
		}
	}
	_, _, err := e.svc.Results(bg, v.ID, "garbage", 2)
	mustValidation(t, err, "cursor")
	if _, _, err := e.svc.Results(bg, "01NOSUCHCHECK000000000000", "", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown check = %v", err)
	}
}

func TestUPT4_RollupsPruningAndUptimeFromBoth(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("r"))
	now := e.clock.Now()
	insert := func(ts time.Time, status string) {
		t.Helper()
		if _, err := e.db.DB().Exec(`INSERT INTO check_results (check_id, ts, status, latency_ms, error_code, detail) VALUES (?, ?, ?, 20, '', '')`, v.ID, ts.UnixMilli(), status); err != nil {
			t.Fatal(err)
		}
	}
	midnight := now.Truncate(24 * time.Hour)
	for d := 1; d <= 100; d++ {
		insert(midnight.AddDate(0, 0, -d).Add(10*time.Hour), "up")
	}
	insert(midnight.AddDate(0, 0, -5).Add(11*time.Hour), "down")
	insert(midnight.AddDate(0, 0, -40).Add(11*time.Hour), "down")
	insert(midnight.AddDate(0, 0, -3).Add(12*time.Hour), "unknown")
	before := e.count(`SELECT count(*) FROM check_results`)

	if err := e.svc.Maintain(bg); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Maintain(bg); err != nil { // idempotent
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM check_rollups_daily WHERE check_id = ?`, v.ID); n != 100 {
		t.Fatalf("rollup rows = %d, want 100 (every day, including those about to be pruned)", n)
	}
	var up, down, avg int
	day := midnight.AddDate(0, 0, -5).Unix()
	if err := e.db.DB().QueryRow(`SELECT up_s, down_s, avg_latency_ms FROM check_rollups_daily WHERE check_id = ? AND day = ?`, v.ID, day).Scan(&up, &down, &avg); err != nil {
		t.Fatal(err)
	}
	if up != 60 || down != 60 || avg != 20 {
		t.Fatalf("rollup = up %d down %d avg %d", up, down, avg)
	}
	cutoff := now.Add(-ResultRetention).UnixMilli()
	if n := e.count(`SELECT count(*) FROM check_results WHERE ts < ?`, cutoff); n != 0 {
		t.Fatalf("%d results older than 90 days survived", n)
	}
	if after := e.count(`SELECT count(*) FROM check_results`); after >= before || after < 85 {
		t.Fatalf("results %d -> %d", before, after)
	}

	want := func(upDays, downs float64) float64 {
		u, d := upDays*60, downs*60
		return math.Round(u/(u+d)*100000) / 1000
	}
	check := func() {
		t.Helper()
		u, err := e.svc.Uptime(bg, v.ID)
		if err != nil {
			t.Fatal(err)
		}
		near(t, u.D30, want(29, 1))
		near(t, u.D90, want(89, 2))
		near(t, u.D7, want(6, 1))
	}
	check()
	// A day that was never rolled up is computed from raw results and gives the same answer.
	if _, err := e.db.DB().Exec(`DELETE FROM check_rollups_daily WHERE check_id = ? AND day >= ?`, v.ID, midnight.AddDate(0, 0, -20).Unix()); err != nil {
		t.Fatal(err)
	}
	check()
	// Rollups outlive raw results by months, then go.
	e.clock.Advance(RollupRetention)
	if err := e.svc.Maintain(bg); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM check_rollups_daily WHERE day < ?`, e.clock.Now().Add(-RollupRetention).Unix()); n != 0 {
		t.Fatalf("%d expired rollups survived", n)
	}
}

func TestUPT4_TickRunsMaintenanceHourly(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("m"))
	old := e.clock.Now().Add(-ResultRetention - time.Hour)
	if _, err := e.db.DB().Exec(`INSERT INTO check_results (check_id, ts, status, latency_ms, error_code, detail) VALUES (?, ?, 'up', 1, '', '')`, v.ID, old.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	e.svc.Tick(bg)
	if e.count(`SELECT count(*) FROM check_results`) != 0 {
		t.Fatal("first tick did not prune")
	}
}

func TestUPT3_StatePersistsAcrossRestart(t *testing.T) {
	e := newEnv(t)
	v := e.create(tcpCheck("persist"))
	e.exec.answers = []probe.Result{downResult}
	_, _ = e.svc.RunNow(bg, v.ID, who)
	again := New(Options{DB: e.db, Secrets: e.svc.box, Clock: e.clock, Inline: true, Exec: e.exec.exec})
	got, err := again.Get(bg, v.ID)
	if err != nil || got.Status.State != StateDown {
		t.Fatalf("after restart: %+v, %v", got.Status, err)
	}
	if err := again.Load(bg); err != nil {
		t.Fatal(err)
	}
	again.mu.Lock()
	_, scheduled := again.next[v.ID]
	again.mu.Unlock()
	if !scheduled {
		t.Fatal("Load did not schedule the check")
	}
}

func TestUPT3_ListGetUpdateDeleteAndETag(t *testing.T) {
	e := newEnv(t)
	a, b, c := e.create(tcpCheck("a")), e.create(tcpCheck("b")), e.create(tcpCheck("c"))
	page, next, err := e.svc.List(bg, "", 2)
	if err != nil || len(page) != 2 || next != page[1].ID || page[0].ID != a.ID {
		t.Fatalf("page 1 = %v next %q err %v", idsOf(page), next, err)
	}
	page, next, _ = e.svc.List(bg, next, 2)
	if len(page) != 1 || page[0].ID != c.ID || next != "" {
		t.Fatalf("page 2 = %v next %q", idsOf(page), next)
	}
	if a.Status.State != StateUnknown || a.Status.LastChecked != nil {
		t.Fatalf("fresh status = %+v", a.Status)
	}
	upd := b.Check
	upd.Name = "b2"
	b2, err := e.svc.Update(bg, b.ID, b.ETag(), upd, who)
	if err != nil || b2.Name != "b2" || b2.ETag() == b.ETag() || b2.CreatedBy != who.UserID {
		t.Fatalf("update = %+v, %v", b2, err)
	}
	if _, err := e.svc.Update(bg, b.ID, b.ETag(), upd, who); !errors.Is(err, ErrStale) {
		t.Fatalf("stale update = %v", err)
	}
	if _, err := e.svc.Update(bg, "01NOSUCHCHECK000000000000", `"c1"`, upd, who); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update = %v", err)
	}
	if err := e.svc.Delete(bg, "01NOSUCHCHECK000000000000", who); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete = %v", err)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action LIKE 'check.%'`) != 4 {
		t.Fatal("create x3 and update must each be audited exactly once")
	}
}

func idsOf(vs []View) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.ID
	}
	return out
}

func ptr[T any](v T) *T { return &v }
