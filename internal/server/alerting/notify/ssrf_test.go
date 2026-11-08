// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// ALR-3: outbound delivery never reaches a blocked destination, including through the IPv6
// forms that embed an IPv4 address.
func TestT11_WebhookRefusesEmbeddedBlockedAddresses(t *testing.T) {
	s := NewSender(Options{Sleep: noSleep, Attempts: 1})
	for _, target := range []string{
		"http://[::169.254.169.254]/latest/meta-data",
		"http://[::ffff:169.254.169.254]/latest/meta-data",
		"http://[64:ff9b::a9fe:a9fe]/latest/meta-data",
		"http://[64:ff9b:1::a9fe:a9fe]/latest/meta-data",
		"http://[2002:a9fe:a9fe::1]/latest/meta-data",
		"http://[::127.0.0.1]:9/",
		"http://[64:ff9b:1::7f00:1]:9/",
	} {
		err := s.Send(context.Background(), "embedded", &Webhook{URL: str(target)}, false, msg(), false)
		if code(err) != errcode.ALRSend003 {
			t.Errorf("%s: err = %v, want ALR-SEND-003", target, err)
		}
	}
}

// ALR-3: a 3xx from a receiver is a permanent failure and its Location is never requested,
// so a redirect to the metadata service cannot be used to reach it.
func TestT11_RedirectToMetadataIsNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	err := newSender(Options{Attempts: 3}).Send(context.Background(), "meta", &Webhook{URL: str(srv.URL)}, false, msg(), false)
	if code(err) != errcode.ALRSend001 {
		t.Errorf("redirect to metadata: %v, want permanent ALR-SEND-001", err)
	}
}

// ALR-3: a redirect to a loopback receiver is not followed even when the policy admits loopback.
func TestT11_RedirectToLoopbackIsNotFollowed(t *testing.T) {
	hits := atomic.Int32{}
	inner := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer inner.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL, http.StatusFound)
	}))
	defer srv.Close()
	err := newSender(Options{Attempts: 1}).Send(context.Background(), "loop", &Webhook{URL: str(srv.URL)}, false, msg(), false)
	if code(err) != errcode.ALRSend001 || hits.Load() != 0 {
		t.Errorf("redirect to loopback: err = %v hits = %d", err, hits.Load())
	}
}

// ALR-3: an SMTP host given by name is judged by the address it resolves to.
func TestT11_SMTPHostnameResolvingToBlockedAddressIsRefused(t *testing.T) {
	s := NewSender(Options{Sleep: noSleep, Attempts: 1})
	c := smtpCfg(25, SecuritySTARTTLS, false)
	c.Host = "localhost"
	if err := s.Send(context.Background(), "smtp-name", c, false, msg(), false); code(err) != errcode.ALRSend003 {
		t.Errorf("localhost resolving to loopback: err = %v, want ALR-SEND-003", err)
	}
	c.Host = "169.254.169.254"
	if err := s.Send(context.Background(), "smtp-meta", c, true, msg(), false); code(err) != errcode.ALRSend003 {
		t.Errorf("metadata with allow_private: err = %v, want ALR-SEND-003", err)
	}
}
