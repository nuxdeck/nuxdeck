// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func msg() Message {
	return Message{
		Kind: KindFiring, AlertID: "01ALERT", Severity: "critical", RuleID: "01RULE", RuleName: "Host offline", RuleKind: "host_offline",
		ItemType: "host", ItemID: "01HOST", ItemName: "web-1", Summary: "agent disconnected", Link: "https://nux.example.com/hosts/01HOST",
		Since: t0, At: t0,
	}
}

func str(s string) Secret { return Secret{Plain: &s} }

func newSender(opts Options) *Sender {
	opts.Policy = loopback
	opts.Sleep = noSleep
	return NewSender(opts)
}

func code(err error) errcode.Code {
	var se *SendError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

// ALR-3: every channel posts its documented payload to the receiver.
func TestALR3_HTTPChannelsPostTheirPayload(t *testing.T) {
	var got struct {
		path string
		body map[string]any
		hdr  http.Header
	}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.path, got.hdr = r.URL.Path, r.Header.Clone()
		got.body = nil
		_ = json.Unmarshal(b, &got.body)
	}))
	defer srv.Close()
	s := newSender(Options{TelegramBase: srv.URL})

	cases := []struct {
		name string
		cfg  Config
		key  string
	}{
		{"slack", &Slack{URL: str(srv.URL + "/slack")}, "text"},
		{"teams", &Teams{URL: str(srv.URL + "/teams")}, "@type"},
		{"discord", &Discord{URL: str(srv.URL + "/discord")}, "embeds"},
		{"telegram", &Telegram{BotToken: str("123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ"), ChatID: "-100123"}, "chat_id"},
		{"webhook", &Webhook{URL: str(srv.URL + "/hook"), Headers: []Header{{Name: "X-Env", Value: "prod"}, {Name: "X-Key", Secret: true, SecretValue: &Secret{Plain: ptr("S3CRET")}}}}, "schema_version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := s.Send(context.Background(), c.name, c.cfg, false, msg(), false); err != nil {
				t.Fatal(err)
			}
			if _, ok := got.body[c.key]; !ok {
				t.Fatalf("payload has no %q: %v", c.key, got.body)
			}
			if !strings.Contains(string(marshal(got.body)), "hosts/01HOST") {
				t.Errorf("payload does not carry the deep link: %v", got.body)
			}
		})
	}
	if got.hdr.Get("X-Env") != "prod" || got.hdr.Get("X-Key") != "S3CRET" || got.hdr.Get("Content-Type") != "application/json" {
		t.Errorf("webhook headers = %v", got.hdr)
	}
	if got.path != "/hook" {
		t.Errorf("last path = %q", got.path)
	}
}

func ptr(s string) *string { return &s }

func TestALR3_WebhookPayloadSchemaIsStable(t *testing.T) {
	m := msg()
	r := t0.Add(time.Minute)
	m.Kind, m.ResolvedAt = KindResolved, &r
	var p map[string]any
	if err := json.Unmarshal(FormatWebhook(m), &p); err != nil {
		t.Fatal(err)
	}
	want := `{"alert":{"flap_count":0,"id":"01ALERT","item":{"id":"01HOST","name":"web-1","type":"host"},"link":"https://nux.example.com/hosts/01HOST","resolved_at":"2026-10-28T12:01:00Z","rule":{"id":"01RULE","kind":"host_offline","name":"Host offline"},"severity":"critical","since":"2026-10-28T12:00:00Z","state":"resolved","summary":"agent disconnected"},"schema_version":1,"sent_at":"2026-10-28T12:00:00Z","test":false,"type":"alert.resolved"}`
	if got := string(marshal(p)); got != want {
		t.Errorf("payload\n got %s\nwant %s", got, want)
	}
}

// Mention and link injection through untrusted names (ALR-3, T11-adjacent).
func TestALR3_UntrustedTextCannotMentionOrLink(t *testing.T) {
	m := msg()
	m.ItemName = "<!channel> @everyone [click](http://evil.example) <https://evil.example|x> <@U123>"
	m.Summary = "@here <!here> https://evil.example/x"
	slack := string(FormatSlack(m))
	for _, bad := range []string{"<!channel>", "<!here>", "<@U123>", "<https://evil", "@everyone", "@here"} {
		if strings.Contains(slack, bad) {
			t.Errorf("slack payload contains %q: %s", bad, slack)
		}
	}
	discord := string(FormatDiscord(m))
	if !strings.Contains(discord, `"allowed_mentions":{"parse":[]}`) || strings.Contains(discord, "](http") || strings.Contains(discord, "@everyone") {
		t.Errorf("discord payload unsafe: %s", discord)
	}
	if teams := string(FormatTeams(m)); strings.Contains(teams, "](http") || strings.Contains(teams, "@everyone") {
		t.Errorf("teams payload unsafe: %s", teams)
	}
	tg := string(FormatTelegram("1", m))
	if strings.Contains(tg, "<!channel>") || strings.Contains(tg, "@everyone") || strings.Contains(tg, "<https") {
		t.Errorf("telegram payload unsafe: %s", tg)
	}
	if !strings.Contains(tg, `\u0026lt;`) {
		t.Errorf("telegram did not HTML-escape: %s", tg)
	}
}

func TestALR3_TestMessageIsLabelled(t *testing.T) {
	m := msg()
	m.Kind = KindTest
	for name, b := range map[string][]byte{"slack": FormatSlack(m), "teams": FormatTeams(m), "discord": FormatDiscord(m), "telegram": FormatTelegram("1", m)} {
		if !strings.Contains(string(b), "TEST") || !strings.Contains(string(b), "test message") {
			t.Errorf("%s test message is not clearly labelled: %s", name, b)
		}
	}
	if !strings.Contains(string(FormatWebhook(m)), `"test":true`) {
		t.Error("webhook test flag missing")
	}
}

// Retries: 5xx and 429 are retried with backoff, 4xx is not.
func TestALR3_RetriesOnTransientOnly(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	cfg := &Slack{URL: str(srv.URL)}

	status.Store(503)
	s := newSender(Options{BreakerThreshold: 100})
	err := s.Send(context.Background(), "a", cfg, false, msg(), false)
	if code(err) != errcode.ALRSend002 || calls.Load() != 3 {
		t.Errorf("5xx: code=%v calls=%d, want ALR-SEND-002 after 3 attempts", code(err), calls.Load())
	}

	calls.Store(0)
	status.Store(404)
	err = s.Send(context.Background(), "b", cfg, false, msg(), false)
	if code(err) != errcode.ALRSend001 || calls.Load() != 1 {
		t.Errorf("4xx: code=%v calls=%d, want ALR-SEND-001 after 1 attempt", code(err), calls.Load())
	}

	calls.Store(0)
	status.Store(429)
	_ = s.Send(context.Background(), "c", cfg, false, msg(), false)
	if calls.Load() != 3 {
		t.Errorf("429 attempts = %d, want 3", calls.Load())
	}
}

func TestALR3_BackoffGrowsExponentiallyWithJitter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	var slept []time.Duration
	s := NewSender(Options{
		Policy: loopback, Backoff: time.Second, Jitter: func(d time.Duration) time.Duration { return d / 10 },
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
	})
	_ = s.Send(context.Background(), "x", &Slack{URL: str(srv.URL)}, false, msg(), false)
	if len(slept) != 2 || slept[0] != 1100*time.Millisecond || slept[1] != 2200*time.Millisecond {
		t.Errorf("sleeps = %v, want [1.1s 2.2s]", slept)
	}
}

func TestALR3_TimeoutIsEnforcedAndTransient(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	s := newSender(Options{Timeout: 50 * time.Millisecond, Attempts: 1})
	start := time.Now()
	err := s.Send(context.Background(), "t", &Slack{URL: str(srv.URL)}, false, msg(), false)
	var se *SendError
	if !errors.As(err, &se) || !se.Transient || se.Detail != "timeout" {
		t.Fatalf("err = %v, want transient timeout", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("timeout not enforced")
	}
}

func TestALR3_BreakerOpensAndHalfOpens(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	now := t0
	s := NewSender(Options{Policy: loopback, Sleep: noSleep, Attempts: 1, BreakerThreshold: 3, BreakerCooldown: time.Minute, Now: func() time.Time { return now }})
	cfg := &Slack{URL: str(srv.URL)}
	for i := 0; i < 3; i++ {
		_ = s.Send(context.Background(), "c", cfg, false, msg(), false)
	}
	if s.BreakerState("c") != "open" {
		t.Fatalf("state = %s, want open", s.BreakerState("c"))
	}
	before := calls.Load()
	if err := s.Send(context.Background(), "c", cfg, false, msg(), false); code(err) != errcode.ALRSend004 {
		t.Errorf("open breaker: %v, want ALR-SEND-004", err)
	}
	if calls.Load() != before {
		t.Error("open breaker still sent a request")
	}
	// Other channels are unaffected.
	if err := s.Send(context.Background(), "other", cfg, false, msg(), false); code(err) == errcode.ALRSend004 {
		t.Error("breaker is not per channel")
	}

	now = now.Add(61 * time.Second)
	if s.BreakerState("c") != "half-open" {
		t.Fatalf("state = %s, want half-open", s.BreakerState("c"))
	}
	status.Store(200)
	if err := s.Send(context.Background(), "c", cfg, false, msg(), false); err != nil {
		t.Fatalf("trial send: %v", err)
	}
	if s.BreakerState("c") != "closed" {
		t.Errorf("state = %s after a successful trial, want closed", s.BreakerState("c"))
	}

	// A failed trial re-opens.
	status.Store(500)
	for i := 0; i < 3; i++ {
		_ = s.Send(context.Background(), "c", cfg, false, msg(), false)
	}
	now = now.Add(61 * time.Second)
	_ = s.Send(context.Background(), "c", cfg, false, msg(), false)
	if s.BreakerState("c") != "open" {
		t.Errorf("state = %s after a failed trial, want open", s.BreakerState("c"))
	}
	// A test send gets through an open breaker.
	status.Store(200)
	if err := s.Send(context.Background(), "c", cfg, false, msg(), true); err != nil {
		t.Errorf("bypass send: %v", err)
	}
}

// T11: the default policy blocks loopback, link-local metadata and private ranges, and
// rebinding is stopped because the dialer checks the connected address.
func TestT11_SSRFBlocked(t *testing.T) {
	hits := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	s := NewSender(Options{Sleep: noSleep}) // strict default policy
	for _, target := range []string{srv.URL, "http://169.254.169.254/latest/meta-data", "http://[::1]:9/", "http://10.0.0.5/hook", "http://localhost:9/"} {
		err := s.Send(context.Background(), "ssrf", &Webhook{URL: str(target)}, false, msg(), false)
		if code(err) != errcode.ALRSend003 {
			t.Errorf("%s: err = %v, want ALR-SEND-003", target, err)
		}
	}
	if hits.Load() != 0 {
		t.Error("a request reached the loopback server")
	}
	// allow_private admits RFC 1918 but never loopback or metadata.
	err := NewSender(Options{Sleep: noSleep, Attempts: 1, Timeout: 200 * time.Millisecond}).Send(context.Background(), "p", &Webhook{URL: str("http://169.254.169.254/")}, true, msg(), false)
	if code(err) != errcode.ALRSend003 {
		t.Errorf("metadata with allow_private: %v", err)
	}
	err = NewSender(Options{Sleep: noSleep}).Send(context.Background(), "p2", &Webhook{URL: str(srv.URL)}, true, msg(), false)
	if code(err) != errcode.ALRSend003 || hits.Load() != 0 {
		t.Errorf("loopback with allow_private: %v hits=%d", err, hits.Load())
	}
}

func TestT11_RebindingBlockedAtConnect(t *testing.T) {
	// The name resolves to a public-looking literal first in a real attack; here the policy
	// is asked about the address the socket connects to, whatever the name was.
	p := probe.Policy{}
	d := p.Dialer(time.Second)
	_, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if !errors.Is(err, probe.ErrBlocked) {
		t.Fatalf("dial = %v, want ErrBlocked", err)
	}
	s := NewSender(Options{Sleep: noSleep})
	if err := s.Send(context.Background(), "r", &Webhook{URL: str("http://127.0.0.1:1/")}, false, msg(), false); code(err) != errcode.ALRSend003 {
		t.Errorf("literal loopback: %v", err)
	}
}

func TestT11_RedirectsAreNotFollowed(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	err := newSender(Options{}).Send(context.Background(), "redir", &Webhook{URL: str(srv.URL)}, false, msg(), false)
	if code(err) != errcode.ALRSend001 {
		t.Errorf("redirect: %v, want permanent ALR-SEND-001", err)
	}
}

func TestALR3_ErrorsNeverContainSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("token=LEAKED-BODY"))
	}))
	defer srv.Close()
	secretPath := "/hooks/SECRET-PATH-TOKEN"
	for _, cfg := range []Config{
		&Slack{URL: str(srv.URL + secretPath)},
		&Telegram{BotToken: str("123456:SECRETTOKENSECRETTOKEN1234"), ChatID: "1"},
	} {
		s := newSender(Options{TelegramBase: srv.URL, Attempts: 1})
		err := s.Send(context.Background(), "e", cfg, false, msg(), false)
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, leak := range []string{"SECRET-PATH-TOKEN", "SECRETTOKEN", "LEAKED-BODY", srv.URL, "127.0.0.1"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error %q contains %q", err, leak)
			}
		}
	}
	if got := RedactURL("https://user:pw@hooks.slack.com/services/T/B/XYZ?x=1"); got != "https://hooks.slack.com" {
		t.Errorf("RedactURL = %q", got)
	}
}

func TestALR3_ResponseBodyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 64<<10)
		for i := 0; i < 64; i++ { // 4 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	if err := newSender(Options{}).Send(context.Background(), "big", &Slack{URL: str(srv.URL)}, false, msg(), false); err != nil {
		t.Fatal(err)
	}
}

// ---- config ----

func TestALR3_ConfigValidation(t *testing.T) {
	good := func(typ, raw string) Config {
		t.Helper()
		c, err := Decode(typ, json.RawMessage(raw))
		if err != nil {
			t.Fatalf("decode %s: %v", typ, err)
		}
		return c
	}
	for _, tc := range []struct {
		name, typ, raw string
		ok             bool
	}{
		{"slack ok", "slack", `{"url":"https://hooks.slack.com/services/T/B/x"}`, true},
		{"slack http", "slack", `{"url":"http://hooks.slack.com/x"}`, false},
		{"slack creds in url", "slack", `{"url":"https://u:p@h.example/x"}`, false},
		{"slack loopback literal", "slack", `{"url":"https://127.0.0.1/x"}`, false},
		{"slack metadata literal", "slack", `{"url":"https://169.254.169.254/x"}`, false},
		{"webhook http ok", "webhook", `{"url":"http://example.com/h"}`, true},
		{"webhook ftp", "webhook", `{"url":"ftp://example.com/h"}`, false},
		{"webhook bad header", "webhook", `{"url":"https://e.com/","headers":[{"name":"Host","value":"x"}]}`, false},
		{"webhook crlf header", "webhook", `{"url":"https://e.com/","headers":[{"name":"X-A","value":"a\r\nX-B: c"}]}`, false},
		{"webhook secret header", "webhook", `{"url":"https://e.com/","headers":[{"name":"X-A","secret":true,"secret_value":"s"}]}`, true},
		{"telegram ok", "telegram", `{"bot_token":"123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ","chat_id":"-100123"}`, true},
		{"telegram bad chat", "telegram", `{"bot_token":"123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ","chat_id":"abc def"}`, false},
		{"smtp ok", "smtp", `{"host":"mail.example.com","from":"nux@example.com","to":["a@example.com"],"username":"u","password":"p"}`, true},
		{"smtp plaintext auth", "smtp", `{"host":"mail.example.com","security":"none","username":"u","password":"p","from":"a@example.com","to":["b@example.com"]}`, false},
		{"smtp none no auth", "smtp", `{"host":"mail.example.com","security":"none","from":"a@example.com","to":["b@example.com"]}`, true},
		{"smtp from crlf", "smtp", `{"host":"m.example.com","from":"a@example.com\r\nBcc: x@evil.test","to":["b@example.com"]}`, false},
		{"smtp to crlf", "smtp", `{"host":"m.example.com","from":"a@example.com","to":["b@example.com\nBcc: x@evil.test"]}`, false},
		{"smtp display name", "smtp", `{"host":"m.example.com","from":"Evil <a@example.com>","to":["b@example.com"]}`, false},
		{"smtp no recipients", "smtp", `{"host":"m.example.com","from":"a@example.com","to":[]}`, false},
		{"smtp bad security", "smtp", `{"host":"m.example.com","security":"ssl","from":"a@example.com","to":["b@example.com"]}`, false},
		{"smtp bad host", "smtp", `{"host":"bad host","from":"a@example.com","to":["b@example.com"]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Decode(tc.typ, json.RawMessage(tc.raw))
			if err == nil {
				err = c.Validate()
			}
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	if _, err := Decode("slack", json.RawMessage(`{"url":"https://a.example/x","extra":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := Decode("sms", nil); err == nil {
		t.Error("unknown type accepted")
	}
	c := good("smtp", `{"host":"m.example.com","from":"a@example.com","to":["b@example.com"]}`).(*SMTP)
	if err := c.Validate(); err != nil || c.Port != 587 || c.Security != SecuritySTARTTLS {
		t.Errorf("defaults: port=%d security=%s err=%v", c.Port, c.Security, err)
	}
	if sl := good("smtp", `{"host":"m.example.com","username":"u","password":"p","from":"a@example.com","to":["b@example.com"]}`).Slots(); len(sl) != 1 {
		t.Errorf("slots = %d, want password only", len(sl))
	}
}

// ---- SMTP ----

func smtpCfg(port int, security string, user bool) *SMTP {
	c := &SMTP{Host: "127.0.0.1", Port: port, Security: security, From: "nux@example.com", To: []string{"oncall@example.com"}}
	if user {
		c.Username, c.Password = "u", str("p")
	}
	return c
}

func TestALR3_SMTPStartTLSWithAuthDeliversMail(t *testing.T) {
	f, s, port := newFakeSMTP(t, true, false)
	if err := s.Send(context.Background(), "m", smtpCfg(port, SecuritySTARTTLS, true), false, msg(), false); err != nil {
		t.Fatal(err)
	}
	if !f.saw("STARTTLS") || !f.authed {
		t.Errorf("starttls=%v authed=%v", f.saw("STARTTLS"), f.authed)
	}
	for _, want := range []string{"Subject: ", "To: oncall@example.com", "text/plain", "hosts/01HOST", "Open in Nux Deck"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("mail lacks %q:\n%s", want, f.data)
		}
	}
	if len(f.rcpts) != 1 || !strings.Contains(f.from, "nux@example.com") {
		t.Errorf("envelope from=%q rcpts=%v", f.from, f.rcpts)
	}
}

func TestALR3_SMTPImplicitTLS(t *testing.T) {
	f, s, port := newFakeSMTP(t, false, true)
	if err := s.Send(context.Background(), "m", smtpCfg(port, SecurityTLS, true), false, msg(), false); err != nil {
		t.Fatal(err)
	}
	if !f.authed || f.data == "" {
		t.Errorf("authed=%v data=%q", f.authed, f.data)
	}
}

func TestALR3_SMTPNeverAuthenticatesOverPlaintext(t *testing.T) {
	// Server does not offer STARTTLS: the client must give up before AUTH.
	f, s, port := newFakeSMTP(t, false, false)
	err := s.Send(context.Background(), "m", smtpCfg(port, SecuritySTARTTLS, true), false, msg(), false)
	if code(err) != errcode.ALRSend005 {
		t.Fatalf("err = %v, want ALR-SEND-005", err)
	}
	if f.saw("AUTH") || f.saw("MAIL") {
		t.Error("client sent AUTH or MAIL over plaintext")
	}
	// Even a hand-built config with security none and credentials is refused.
	err = s.Send(context.Background(), "m2", smtpCfg(port, SecurityNone, true), false, msg(), false)
	if code(err) != errcode.ALRSend005 || f.saw("AUTH") {
		t.Errorf("none+auth: %v authSeen=%v", err, f.saw("AUTH"))
	}
	// Plain mail without credentials over security none works.
	if err := s.Send(context.Background(), "m3", smtpCfg(port, SecurityNone, false), false, msg(), false); err != nil {
		t.Errorf("none without auth: %v", err)
	}
}

func TestALR3_SMTPWrongPasswordIsAuthError(t *testing.T) {
	_, s, port := newFakeSMTP(t, true, false)
	c := smtpCfg(port, SecuritySTARTTLS, true)
	c.Password = str("wrong")
	if err := s.Send(context.Background(), "m", c, false, msg(), false); code(err) != errcode.ALRSend005 {
		t.Errorf("err = %v, want ALR-SEND-005", err)
	}
}

func TestALR3_SMTPCertificateMustVerify(t *testing.T) {
	_, _, port := newFakeSMTP(t, true, false)
	s := NewSender(Options{Policy: loopback, Sleep: noSleep}) // no test roots
	if err := s.Send(context.Background(), "m", smtpCfg(port, SecuritySTARTTLS, true), false, msg(), false); code(err) != errcode.ALRSend005 {
		t.Errorf("err = %v, want ALR-SEND-005 for an untrusted certificate", err)
	}
}

func TestALR3_SMTPHeaderInjectionIsNeutralised(t *testing.T) {
	m := msg()
	m.ItemName = "web-1\r\nBcc: attacker@evil.test"
	m.RuleName = "Rule\nX-Injected: yes"
	m.Summary = "line\r\n\r\nInjected: body"
	mail := string(buildMail(smtpCfg(25, SecuritySTARTTLS, false), m, t0))
	header := mail[:strings.Index(mail, "\r\n\r\n")]
	for _, l := range strings.Split(header, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "bcc:") || strings.HasPrefix(l, "X-Injected") {
			t.Errorf("injected header line: %q", l)
		}
	}
	if strings.Contains(EmailSubject(m), "\n") || strings.Contains(EmailSubject(m), "\r") {
		t.Error("subject has a line break")
	}
	// The configuration itself refuses CR/LF in addresses (see ConfigValidation).
	if _, err := bareAddress("a@example.com\r\nBcc: x@y.test"); err == nil {
		t.Error("address with CRLF accepted")
	}
}

func TestALR3_SMTPBlockedDestination(t *testing.T) {
	s := NewSender(Options{Sleep: noSleep})
	c := smtpCfg(25, SecuritySTARTTLS, false)
	c.Host = "169.254.169.254"
	if err := s.Send(context.Background(), "m", c, false, msg(), false); code(err) != errcode.ALRSend003 {
		t.Errorf("err = %v", err)
	}
	c.Host = "127.0.0.1"
	if err := s.Send(context.Background(), "m", c, false, msg(), false); code(err) != errcode.ALRSend003 {
		t.Errorf("loopback err = %v", err)
	}
}

func TestALR3_SMTPConnectionRefusedIsTransient(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	s := newSender(Options{Attempts: 2})
	err := s.Send(context.Background(), "m", smtpCfg(port, SecuritySTARTTLS, false), false, msg(), false)
	var se *SendError
	if !errors.As(err, &se) || !se.Transient {
		t.Errorf("err = %v, want transient", err)
	}
}

func TestBreakerCountsFailuresOnly(t *testing.T) {
	b := &breaker{threshold: 2, cooldown: time.Minute}
	b.record(t0, false)
	b.record(t0, true)
	b.record(t0, false)
	if !b.allow(t0) {
		t.Error("non-consecutive failures opened the breaker")
	}
}
