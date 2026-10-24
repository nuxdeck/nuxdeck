// SPDX-License-Identifier: AGPL-3.0-only

package tlsutil

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func leaf(t *testing.T, o Options) *x509.Certificate {
	t.Helper()
	c, err := Certificate(o)
	if err != nil {
		t.Fatal(err)
	}
	l, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestGeneratesSelfSignedCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := leaf(t, Options{DataDir: dir, Hostnames: []string{"nux.example", "10.0.0.5"}, Now: func() time.Time { return now }})

	for _, h := range []string{"localhost", "127.0.0.1", "::1", "nux.example", "10.0.0.5"} {
		if err := l.VerifyHostname(h); err != nil {
			t.Errorf("certificate does not cover %s: %v", h, err)
		}
	}
	if got := l.NotAfter.Sub(now); got < 364*24*time.Hour || got > 366*24*time.Hour {
		t.Errorf("validity = %s, want about one year", got)
	}
	info, err := os.Stat(filepath.Join(dir, "tls", "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600", perm)
	}
}

func TestReusesAndRenews(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(d time.Time) Options { return Options{DataDir: dir, Now: func() time.Time { return d }} }

	first := leaf(t, at(start))
	if again := leaf(t, at(start.Add(24*time.Hour))); again.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Error("a valid certificate was regenerated")
	}
	if renewed := leaf(t, at(start.Add(340*24*time.Hour))); renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("a certificate inside the renewal window was kept")
	}
}

func TestRegeneratesWhenNamesChange(t *testing.T) {
	dir := t.TempDir()
	first := leaf(t, Options{DataDir: dir})
	second := leaf(t, Options{DataDir: dir, Hostnames: []string{"new.example"}})
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Error("certificate was reused although a requested name is missing")
	}
	if err := second.VerifyHostname("new.example"); err != nil {
		t.Error(err)
	}
}

func TestSuppliedCertificate(t *testing.T) {
	gen := t.TempDir()
	leaf(t, Options{DataDir: gen})
	supplied := Options{
		CertFile: filepath.Join(gen, "tls", "server.crt"),
		KeyFile:  filepath.Join(gen, "tls", "server.key"),
		DataDir:  t.TempDir(),
	}
	if _, err := Certificate(supplied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(supplied.DataDir, "tls")); err == nil {
		t.Error("a supplied certificate must not create a generated pair")
	}

	supplied.KeyFile = filepath.Join(gen, "missing.key")
	if _, err := Certificate(supplied); errcode.CodeOf(err) != errcode.SRVIO002 {
		t.Errorf("code = %q, want %q", errcode.CodeOf(err), errcode.SRVIO002)
	}
}
