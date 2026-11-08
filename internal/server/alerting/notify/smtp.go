// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const smtpOverall = 30 * time.Second

// plainAuth is SMTP PLAIN without the stdlib's host-name exemptions: sendSMTP only calls it
// once the connection is encrypted.
type plainAuth struct{ user, pass string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, fmt.Errorf("unexpected server challenge")
	}
	return nil, nil
}

func (s *Sender) tlsConfig(host string) *tls.Config {
	c := s.opts.TLS.Clone()
	if c == nil {
		c = &tls.Config{}
	}
	c.ServerName = host
	if c.MinVersion < tls.VersionTLS12 {
		c.MinVersion = tls.VersionTLS12
	}
	return c
}

func (s *Sender) sendSMTP(ctx context.Context, c *SMTP, allowPrivate bool, m Message) *SendError {
	ctx, cancel := context.WithTimeout(ctx, smtpOverall)
	defer cancel()
	conn, err := s.policy(allowPrivate).Dialer(s.opts.Timeout).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if err != nil {
		return classifyNetErr(err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	secure := false
	if c.Security == SecurityTLS {
		tc := tls.Client(conn, s.tlsConfig(c.Host))
		if err := tc.HandshakeContext(ctx); err != nil {
			return fail(errcode.ALRSend005, false, "tls handshake failed")
		}
		conn, secure = tc, true
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return smtpReplyError(err)
	}
	defer func() { _ = cl.Close() }()
	if err := cl.Hello("nuxd"); err != nil {
		return smtpReplyError(err)
	}
	if c.Security == SecuritySTARTTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return fail(errcode.ALRSend005, false, "server does not offer starttls")
		}
		if err := cl.StartTLS(s.tlsConfig(c.Host)); err != nil {
			return fail(errcode.ALRSend005, false, "starttls failed")
		}
		secure = true
	}
	if c.Username != "" {
		if !secure {
			return fail(errcode.ALRSend005, false, "refusing to authenticate without encryption")
		}
		if err := cl.Auth(plainAuth{c.Username, plainSecret(c.Password)}); err != nil {
			return smtpReplyError(err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return smtpReplyError(err)
	}
	for _, to := range c.To {
		if err := cl.Rcpt(to); err != nil {
			return smtpReplyError(err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return smtpReplyError(err)
	}
	if _, err := w.Write(buildMail(c, m, s.opts.Now())); err != nil {
		return smtpReplyError(err)
	}
	if err := w.Close(); err != nil {
		return smtpReplyError(err)
	}
	_ = cl.Quit()
	return nil
}

// buildMail assembles the RFC 5322 message. Every header value is built from validated
// addresses or text with line breaks removed, so no input can add a header.
func buildMail(c *SMTP, m Message, now time.Time) []byte {
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + oneLine(v) + "\r\n") }
	h("From", "Nux Deck <"+c.From+">")
	h("To", strings.Join(c.To, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", EmailSubject(m)))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(EmailBody(m)))
	_ = qp.Close()
	return b.Bytes()
}
