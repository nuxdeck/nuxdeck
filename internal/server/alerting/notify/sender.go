// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/textproto"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// Defaults.
const (
	DefaultTimeout          = 10 * time.Second
	DefaultAttempts         = 3
	DefaultBackoff          = 500 * time.Millisecond
	DefaultBreakerThreshold = 5
	DefaultBreakerCooldown  = time.Minute
	// maxResponseBytes caps what is read from a receiver; the body is discarded anyway.
	maxResponseBytes = 4 << 10
	telegramBase     = "https://api.telegram.org"
	userAgent        = "nuxd-alerting/1"
)

// SendError is a delivery failure. Detail is a fixed phrase and never holds the URL, token or
// anything the receiver sent back.
type SendError struct {
	Code      errcode.Code
	Transient bool
	Detail    string
}

func (e *SendError) Error() string { return string(e.Code) + ": " + e.Detail }

func fail(code errcode.Code, transient bool, detail string) *SendError {
	return &SendError{Code: code, Transient: transient, Detail: detail}
}

// Options configure a Sender. Zero values select the defaults.
type Options struct {
	Log     *slog.Logger
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	Timeout time.Duration
	// Attempts is the most tries per send, including the first.
	Attempts         int
	Backoff          time.Duration
	BreakerThreshold int
	BreakerCooldown  time.Duration

	// The fields below exist for tests.

	// Policy overrides the SSRF policy; nil uses probe.Policy{AllowPrivate: allowPrivate}.
	Policy func(allowPrivate bool) probe.Policy
	// TLS adds roots for the receivers' certificates.
	TLS *tls.Config
	// TelegramBase replaces https://api.telegram.org.
	TelegramBase string
	// Jitter returns the random extra delay for a backoff step; nil uses up to half of it.
	Jitter func(d time.Duration) time.Duration
}

// Sender delivers messages. It is safe for concurrent use.
type Sender struct {
	opts Options
	mu   sync.Mutex
	brk  map[string]*breaker
}

// NewSender builds a Sender.
func NewSender(o Options) *Sender {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Attempts <= 0 {
		o.Attempts = DefaultAttempts
	}
	if o.Backoff <= 0 {
		o.Backoff = DefaultBackoff
	}
	if o.BreakerThreshold <= 0 {
		o.BreakerThreshold = DefaultBreakerThreshold
	}
	if o.BreakerCooldown <= 0 {
		o.BreakerCooldown = DefaultBreakerCooldown
	}
	if o.TelegramBase == "" {
		o.TelegramBase = telegramBase
	}
	if o.Jitter == nil {
		o.Jitter = func(d time.Duration) time.Duration {
			if d <= 1 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(d / 2))) //nolint:gosec // jitter needs no CSPRNG
		}
	}
	return &Sender{opts: o, brk: map[string]*breaker{}}
}

func (s *Sender) breaker(id string) *breaker {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.brk[id]
	if !ok {
		b = &breaker{threshold: s.opts.BreakerThreshold, cooldown: s.opts.BreakerCooldown}
		s.brk[id] = b
	}
	return b
}

// Forget drops the breaker of a deleted channel.
func (s *Sender) Forget(id string) {
	s.mu.Lock()
	delete(s.brk, id)
	s.mu.Unlock()
}

// BreakerState reports "closed", "open" or "half-open" for a channel.
func (s *Sender) BreakerState(id string) string { return s.breaker(id).state(s.opts.Now()) }

// Send delivers m through the channel cfg, with retries on transient errors and a circuit
// breaker per channel id. A test send (bypassBreaker) is attempted even while the breaker is
// open, so an administrator can verify a repaired channel; its outcome still feeds the breaker.
// The returned error is nil or a *SendError.
func (s *Sender) Send(ctx context.Context, channelID string, cfg Config, allowPrivate bool, m Message, bypassBreaker bool) error {
	b := s.breaker(channelID)
	if !bypassBreaker && !b.allow(s.opts.Now()) {
		return fail(errcode.ALRSend004, false, "circuit open")
	}
	var err *SendError
	for attempt := 1; attempt <= s.opts.Attempts; attempt++ {
		err = s.once(ctx, cfg, allowPrivate, m)
		if err == nil || !err.Transient || attempt == s.opts.Attempts {
			break
		}
		d := s.opts.Backoff << (attempt - 1)
		d += s.opts.Jitter(d)
		if serr := s.opts.Sleep(ctx, d); serr != nil {
			err = fail(errcode.ALRSend002, false, "cancelled")
			break
		}
	}
	// A blocked destination is a configuration error, not a sick receiver: it must not trip the breaker.
	if err != nil && err.Code == errcode.ALRSend003 {
		b.record(s.opts.Now(), true)
		return err
	}
	b.record(s.opts.Now(), err == nil)
	if err != nil {
		return err
	}
	return nil
}

func (s *Sender) policy(allowPrivate bool) probe.Policy {
	if s.opts.Policy != nil {
		return s.opts.Policy(allowPrivate)
	}
	return probe.Policy{AllowPrivate: allowPrivate}
}

func (s *Sender) once(ctx context.Context, cfg Config, allowPrivate bool, m Message) *SendError {
	switch c := cfg.(type) {
	case *SMTP:
		return s.sendSMTP(ctx, c, allowPrivate, m)
	case *Slack:
		return s.post(ctx, plainSecret(c.URL), FormatSlack(m), nil, allowPrivate)
	case *Teams:
		return s.post(ctx, plainSecret(c.URL), FormatTeams(m), nil, allowPrivate)
	case *Discord:
		return s.post(ctx, plainSecret(c.URL), FormatDiscord(m), nil, allowPrivate)
	case *Telegram:
		return s.post(ctx, s.opts.TelegramBase+"/bot"+plainSecret(c.BotToken)+"/sendMessage", FormatTelegram(c.ChatID, m), nil, allowPrivate)
	case *Webhook:
		h := http.Header{}
		for _, hd := range c.Headers {
			if hd.Secret && hd.SecretValue != nil {
				h.Set(hd.Name, plainSecret(*hd.SecretValue))
			} else {
				h.Set(hd.Name, hd.Value)
			}
		}
		return s.post(ctx, plainSecret(c.URL), FormatWebhook(m), h, allowPrivate)
	default:
		return fail(errcode.ALRSend001, false, "unsupported channel type")
	}
}

func plainSecret(s Secret) string {
	if s.Plain == nil {
		return ""
	}
	return *s.Plain
}

// client never follows redirects and never uses a proxy: both would bypass the dialer's check.
func (s *Sender) client(allowPrivate bool) *http.Client {
	tlsCfg := s.opts.TLS.Clone()
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout: s.opts.Timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         s.policy(allowPrivate).DialContext(s.opts.Timeout),
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: s.opts.Timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *Sender) post(ctx context.Context, target string, body []byte, extra http.Header, allowPrivate bool) *SendError {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fail(errcode.ALRSend001, false, "invalid url")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range extra {
		req.Header[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	resp, err := s.client(allowPrivate).Do(req)
	if err != nil {
		// err is a *url.Error holding the full URL: classify it, never pass it on.
		return classifyNetErr(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fail(errcode.ALRSend002, true, fmt.Sprintf("status %d", resp.StatusCode))
	default:
		return fail(errcode.ALRSend001, false, fmt.Sprintf("status %d", resp.StatusCode))
	}
}

func classifyNetErr(err error) *SendError {
	var (
		unknown x509.UnknownAuthorityError
		host    x509.HostnameError
		inval   x509.CertificateInvalidError
	)
	switch {
	case errors.Is(err, probe.ErrBlocked):
		return fail(errcode.ALRSend003, false, "destination blocked")
	case errors.As(err, &unknown), errors.As(err, &host), errors.As(err, &inval):
		return fail(errcode.ALRSend002, false, "certificate not trusted")
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fail(errcode.ALRSend002, true, "timeout")
	case errors.Is(err, context.Canceled):
		return fail(errcode.ALRSend002, false, "cancelled")
	default:
		return fail(errcode.ALRSend002, true, "connection failed")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// textprotoToSendError maps an SMTP reply to a failure: 4xx is transient, 535 and 534 are
// authentication, other 5xx are permanent.
func smtpReplyError(err error) *SendError {
	var te *textproto.Error
	if errors.As(err, &te) {
		switch {
		case te.Code >= 400 && te.Code < 500:
			return fail(errcode.ALRSend002, true, fmt.Sprintf("smtp %d", te.Code))
		case te.Code == 535 || te.Code == 534 || te.Code == 530:
			return fail(errcode.ALRSend005, false, fmt.Sprintf("smtp %d", te.Code))
		default:
			return fail(errcode.ALRSend001, false, fmt.Sprintf("smtp %d", te.Code))
		}
	}
	return classifyNetErr(err)
}
