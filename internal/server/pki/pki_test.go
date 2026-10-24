// SPDX-License-Identifier: AGPL-3.0-only

package pki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

var epoch = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type env struct {
	t     *testing.T
	dir   string
	db    *store.Store
	ca    *pki.CA
	svc   *pki.Service
	actor pki.Actor
	now   atomic.Int64 // unix milliseconds
}

func (e *env) clock() time.Time { return time.UnixMilli(e.now.Load()).UTC() }

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir()}
	e.now.Store(epoch.UnixMilli())

	db, err := store.Open(context.Background(), e.dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.Now = e.clock
	e.db = db

	if err := db.CreateAdmin(context.Background(),
		auth.User{ID: "01ADMIN", Email: "ada@example.com", Name: "Ada", PasswordHash: "x", CreatedAt: epoch},
		audit.Event{ActorType: "user", ActorID: "01ADMIN", Action: "setup.complete", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if e.ca, err = pki.LoadOrCreateCA(filepath.Join(e.dir, "pki"), epoch); err != nil {
		t.Fatal(err)
	}
	e.svc = pki.NewService(db, e.ca)
	e.svc.Now = e.clock
	e.actor = pki.Actor{UserID: "01ADMIN", IP: "198.51.100.7"}
	return e
}

func (e *env) token(req pki.TokenRequest) string {
	e.t.Helper()
	if req.ServerURL == "" {
		req.ServerURL = "https://nux.example.com:8444"
	}
	c, err := e.svc.CreateToken(context.Background(), e.actor, req)
	if err != nil {
		e.t.Fatal(err)
	}
	return c.Token
}

func csr(t *testing.T, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (e *env) enroll(token string, csrDER []byte) (*pki.Enrollment, error) {
	return e.svc.Enroll(context.Background(), pki.EnrollRequest{
		Token: token, CSRDER: csrDER, Version: "0.1.0", Hostname: "web-1", OS: "linux", Arch: "amd64", IP: "203.0.113.9",
	})
}

func wantCode(t *testing.T, err error, want errcode.Code) {
	t.Helper()
	if got := errcode.CodeOf(err); got != want {
		t.Fatalf("code = %q (%v), want %s", got, err, want)
	}
}

func TestAGT1_TokenWorksOnce(t *testing.T) {
	e := newEnv(t)
	tok := e.token(pki.TokenRequest{})
	der := csr(t, &x509.CertificateRequest{})

	if _, err := e.enroll(tok, der); err != nil {
		t.Fatal(err)
	}
	_, err := e.enroll(tok, der)
	wantCode(t, err, errcode.GWTok001)
}

func TestAGT1_TokenExpiresAfterOneHourByDefault(t *testing.T) {
	e := newEnv(t)
	tok := e.token(pki.TokenRequest{})
	der := csr(t, &x509.CertificateRequest{})

	e.now.Store(epoch.Add(time.Hour + time.Second).UnixMilli())
	_, err := e.enroll(tok, der)
	wantCode(t, err, errcode.GWTok001)

	fresh := e.token(pki.TokenRequest{})
	e.now.Add(int64((time.Hour - time.Second) / time.Millisecond))
	if _, err := e.enroll(fresh, der); err != nil {
		t.Errorf("a token one second before expiry must still work: %v", err)
	}
}

func TestAGT1_ConcurrentRedemptionSpendsTheTokenOnce(t *testing.T) {
	e := newEnv(t)
	tok := e.token(pki.TokenRequest{})
	der := csr(t, &x509.CertificateRequest{})

	const n = 12
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.enroll(tok, der); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d enrolments succeeded with one token, want exactly 1", wins.Load())
	}
}

func TestAGT1_UnknownAndMalformedTokensAreRefused(t *testing.T) {
	e := newEnv(t)
	der := csr(t, &x509.CertificateRequest{})
	other, _ := pki.NewToken("https://nux.example.com:8444", e.ca.Fingerprint())

	for name, tok := range map[string]string{"never issued": other.String(), "empty": "", "garbage": "nuxtok1.a.b.c", "wrong version": "nuxtok2.a.b.c"} {
		_, err := e.enroll(tok, der)
		if errcode.CodeOf(err) != errcode.GWTok001 {
			t.Errorf("%s: got %v, want %s", name, err, errcode.GWTok001)
		}
	}
}

func TestAGT1_OnlyAHashIsStored(t *testing.T) {
	e := newEnv(t)
	tokStr := e.token(pki.TokenRequest{})
	tok, err := pki.ParseToken(tokStr)
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var stored string
	if err := db.QueryRow(`SELECT token_hash FROM enrollment_tokens`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != tok.Hash() || stored == tok.Secret || stored == tokStr {
		t.Errorf("stored value %q is not just the hash of the secret", stored)
	}
}

func TestAGT3_TokenCarriesTheCAFingerprint(t *testing.T) {
	e := newEnv(t)
	tok, err := pki.ParseToken(e.token(pki.TokenRequest{ServerURL: "https://nux.example.com:8444"}))
	if err != nil {
		t.Fatal(err)
	}
	if tok.CAFingerprint != e.ca.Fingerprint() {
		t.Errorf("fingerprint = %s, want %s", tok.CAFingerprint, e.ca.Fingerprint())
	}
	if tok.ServerURL != "https://nux.example.com:8444" {
		t.Errorf("server URL = %q", tok.ServerURL)
	}

	got, err := e.enroll(tok.String(), csr(t, &x509.CertificateRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if pki.Fingerprint(got.CACertDER) != tok.CAFingerprint {
		t.Error("the CA certificate handed to the agent does not match the fingerprint in its token")
	}
}

func TestIssuedCertificateIsTheServersNotTheRequests(t *testing.T) {
	e := newEnv(t)
	hostile := csr(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "admin", Organization: []string{"root"}},
		DNSNames:    []string{"nuxd.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		URIs:        []*url.URL{pki.AgentURI("01SOMEONEELSE")},
	})
	got, err := e.enroll(e.token(pki.TokenRequest{}), hostile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(got.CertDER)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != got.AgentID || len(cert.Subject.Organization) != 0 {
		t.Errorf("subject = %v, want only CN=%s", cert.Subject, got.AgentID)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != pki.AgentURI(got.AgentID).String() {
		t.Errorf("SANs came from the request: dns=%v ip=%v uri=%v", cert.DNSNames, cert.IPAddresses, cert.URIs)
	}
	if cert.IsCA {
		t.Error("an agent certificate must not be a CA")
	}
	if got := cert.NotAfter.Sub(epoch); got != pki.CertTTL {
		t.Errorf("valid for %v, want %v", got, pki.CertTTL)
	}
	if got.RenewAfter.Sub(epoch) != pki.RenewAfter {
		t.Errorf("renew after %v, want %v", got.RenewAfter.Sub(epoch), pki.RenewAfter)
	}

	_, err = cert.Verify(x509.VerifyOptions{Roots: e.ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: epoch.Add(time.Hour)})
	if err != nil {
		t.Errorf("certificate does not verify against the CA as a client certificate: %v", err)
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: e.ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: epoch.Add(time.Hour)})
	if err == nil {
		t.Error("an agent certificate must not work as a server certificate")
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: e.ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: epoch.Add(25 * time.Hour)})
	if err == nil {
		t.Error("the certificate must expire after 24 hours")
	}
}

func TestBadRequestsAreRejectedWithoutSpendingTheToken(t *testing.T) {
	e := newEnv(t)
	tok := e.token(pki.TokenRequest{})

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rsaKey)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, edKey)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p224CSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, p224)
	tampered := csr(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web-1"}})
	tampered[len(tampered)-1] ^= 0xff

	for name, der := range map[string][]byte{"rsa": rsaCSR, "ed25519": edCSR, "p224": p224CSR, "bad signature": tampered, "garbage": []byte("nope"), "empty": nil} {
		_, err := e.enroll(tok, der)
		if errcode.CodeOf(err) != errcode.GWCSR001 {
			t.Errorf("%s: got %v, want %s", name, err, errcode.GWCSR001)
		}
	}
	if _, err := e.enroll(tok, csr(t, &x509.CertificateRequest{})); err != nil {
		t.Errorf("the token must survive rejected requests: %v", err)
	}
}

func TestIssueFailureKeepsTheTokenAndWritesNoAudit(t *testing.T) {
	e := newEnv(t)
	tok, _ := pki.ParseToken(e.token(pki.TokenRequest{}))
	before, _ := e.db.VerifyAuditChain(context.Background())

	boom := errors.New("signer offline")
	err := e.db.RedeemEnrollmentToken(context.Background(), tok.Hash(), epoch, func(string, string) (pki.Redemption, error) {
		return pki.Redemption{}, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the callback's error", err)
	}
	if after, _ := e.db.VerifyAuditChain(context.Background()); after != before {
		t.Errorf("audit entries went from %d to %d on a rolled-back redemption", before, after)
	}
	if _, err := e.enroll(tok.String(), csr(t, &x509.CertificateRequest{})); err != nil {
		t.Errorf("token was spent by a failed redemption: %v", err)
	}
}

func TestEveryChangeIsAuditedAndTheChainHolds(t *testing.T) {
	e := newEnv(t)
	base, _ := e.db.VerifyAuditChain(context.Background())

	tok := e.token(pki.TokenRequest{Labels: map[string]string{"env": "prod"}})   // +1
	if _, err := e.enroll(tok, csr(t, &x509.CertificateRequest{})); err != nil { // +1
		t.Fatal(err)
	}
	_, _ = e.enroll(tok, csr(t, &x509.CertificateRequest{})) // reused: +1 failure
	_, _ = e.enroll("junk", nil)                             // malformed: +1 failure

	n, err := e.db.VerifyAuditChain(context.Background())
	if err != nil || n != base+4 {
		t.Errorf("audit chain: %d entries (want %d), %v", n, base+4, err)
	}
}

func TestTokenRequestLimits(t *testing.T) {
	e := newEnv(t)
	tooMany := map[string]string{}
	for i := range 21 {
		tooMany[string(rune('a'+i))] = "v"
	}
	for name, req := range map[string]pki.TokenRequest{
		"ttl over 24h": {ServerURL: "https://x.example.com", TTL: 25 * time.Hour},
		"negative ttl": {ServerURL: "https://x.example.com", TTL: -time.Second},
		"http url":     {ServerURL: "http://x.example.com"},
		"no url":       {ServerURL: "-"},
		"many labels":  {ServerURL: "https://x.example.com", Labels: tooMany},
	} {
		_, err := e.svc.CreateToken(context.Background(), e.actor, req)
		var fe *pki.FieldError
		if !errors.As(err, &fe) {
			t.Errorf("%s: got %v, want a FieldError", name, err)
		}
	}
}

func TestCAPersistsAndIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	first, err := pki.LoadOrCreateCA(dir, epoch)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	again, err := pki.LoadOrCreateCA(dir, epoch.Add(24*time.Hour))
	if err != nil || again.Fingerprint() != first.Fingerprint() {
		t.Errorf("reloaded CA differs: %v", err)
	}
}

func TestCARefusesToReplaceOrTrustBrokenState(t *testing.T) {
	other, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "pki"), epoch)
	if err != nil {
		t.Fatal(err)
	}
	_ = other

	t.Run("orphan key is not replaced", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "pki")
		if _, err := pki.LoadOrCreateCA(dir, epoch); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "ca.crt")); err != nil {
			t.Fatal(err)
		}
		_, err := pki.LoadOrCreateCA(dir, epoch)
		wantCode(t, err, errcode.GWCA001)
	})
	t.Run("certificate and key from different CAs", func(t *testing.T) {
		a, b := filepath.Join(t.TempDir(), "pki"), filepath.Join(t.TempDir(), "pki")
		for _, d := range []string{a, b} {
			if _, err := pki.LoadOrCreateCA(d, epoch); err != nil {
				t.Fatal(err)
			}
		}
		cert, _ := os.ReadFile(filepath.Join(b, "ca.crt"))                            //nolint:gosec // test fixture
		if err := os.WriteFile(filepath.Join(a, "ca.crt"), cert, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		_, err := pki.LoadOrCreateCA(a, epoch)
		wantCode(t, err, errcode.GWCA001)
	})
	t.Run("expired", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "pki")
		if _, err := pki.LoadOrCreateCA(dir, epoch); err != nil {
			t.Fatal(err)
		}
		_, err := pki.LoadOrCreateCA(dir, epoch.AddDate(11, 0, 0))
		wantCode(t, err, errcode.GWCA001)
	})
}

func TestParseTokenRejectsMalformedShapes(t *testing.T) {
	good, _ := pki.NewToken("https://nux.example.com:8444", pki.Fingerprint([]byte("ca")))
	if _, err := pki.ParseToken(good.String()); err != nil {
		t.Fatalf("a freshly built token must parse: %v", err)
	}
	bad, _ := pki.NewToken("http://nux.example.com", pki.Fingerprint([]byte("ca")))
	short := good
	short.Secret = "c2hvcnQ"
	badFP := good
	badFP.CAFingerprint = "abcd"
	for name, s := range map[string]string{"http scheme": bad.String(), "short secret": short.String(), "short fingerprint": badFP.String(), "extra part": good.String() + ".x"} {
		if _, err := pki.ParseToken(s); errcode.CodeOf(err) != errcode.GWTok001 {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
