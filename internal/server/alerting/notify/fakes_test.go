// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// loopback lets tests reach httptest and fake SMTP servers.
func loopback(bool) probe.Policy { return probe.Policy{AllowLoopback: true, AllowPrivate: true} }

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// fakeSMTP is a tiny SMTP server recording what a client does.
type fakeSMTP struct {
	ln       net.Listener
	cert     tls.Certificate
	starttls bool // advertise STARTTLS
	implicit bool // TLS from the first byte
	user     string
	pass     string

	mu       sync.Mutex
	commands []string
	authed   bool
	data     string
	rcpts    []string
	from     string
}

func newFakeSMTP(t *testing.T, starttls, implicit bool) (*fakeSMTP, *Sender, int) {
	t.Helper()
	cert, pool := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, cert: cert, starttls: starttls, implicit: implicit, user: "u", pass: "p"}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	s := NewSender(Options{Policy: loopback, TLS: &tls.Config{RootCAs: pool}, Sleep: noSleep, Timeout: 5 * time.Second})
	return f, s, ln.Addr().(*net.TCPAddr).Port
}

func (f *fakeSMTP) log(s string) {
	f.mu.Lock()
	f.commands = append(f.commands, s)
	f.mu.Unlock()
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	if f.implicit {
		c = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	}
	r := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	w("220 fake ESMTP")
	secure := f.implicit
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.Fields(line + " x")[0])
		f.log(verb)
		switch verb {
		case "EHLO", "HELO":
			ext := "250-fake\r\n250-AUTH PLAIN\r\n"
			if f.starttls && !secure {
				ext += "250-STARTTLS\r\n"
			}
			_, _ = c.Write([]byte(ext + "250 8BITMIME\r\n"))
		case "STARTTLS":
			w("220 go ahead")
			c = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			r = bufio.NewReader(c)
			secure = true
		case "AUTH":
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			if string(raw) == "\x00"+f.user+"\x00"+f.pass {
				f.mu.Lock()
				f.authed = true
				f.mu.Unlock()
				w("235 ok")
			} else {
				w("535 bad credentials")
			}
		case "MAIL":
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			w("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line)
			f.mu.Unlock()
			w("250 ok")
		case "DATA":
			w("354 go")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			f.mu.Lock()
			f.data = sb.String()
			f.mu.Unlock()
			w("250 queued")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func (f *fakeSMTP) saw(verb string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if c == verb {
			return true
		}
	}
	return false
}

func noSleep(_ context.Context, _ time.Duration) error { return nil }
