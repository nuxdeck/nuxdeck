// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver for raw reads

	"github.com/nuxdeck/nuxdeck/internal/agent/enroll"
	"github.com/nuxdeck/nuxdeck/internal/agent/identity"
	"github.com/nuxdeck/nuxdeck/internal/agent/run"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

var fastBackoff = func() *run.Backoff { return &run.Backoff{Min: 20 * time.Millisecond, Max: 100 * time.Millisecond} }

func (e *env) enrollReq(dir, token string) enroll.Request {
	return enroll.Request{StateDir: dir, Token: token, Version: "0.1.0", Hostname: "web-1", OS: "linux", Arch: "amd64"}
}

func (e *env) enrollAgent(dir string) string {
	e.t.Helper()
	id, err := enroll.Do(context.Background(), e.enrollReq(dir, e.token()))
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

type running struct {
	done chan error
	stop context.CancelFunc
}

func (e *env) runAgent(dir string, tweak func(*run.Config)) *running {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := run.Config{StateDir: dir, Version: "0.1.0", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Heartbeat: 50 * time.Millisecond, Backoff: fastBackoff()}
	if tweak != nil {
		tweak(&cfg)
	}
	r := &running{done: make(chan error, 1), stop: cancel}
	go func() { r.done <- run.Run(ctx, cfg) }()
	e.t.Cleanup(cancel)
	return r
}

func (r *running) wait(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(within):
		t.Fatal("the agent did not stop in time")
		return nil
	}
}

func TestAgentEnrolsAndStaysConnected(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(t.TempDir(), "state")
	id := e.enrollAgent(dir)

	loaded, err := identity.Load(dir)
	if err != nil || loaded.AgentID != id {
		t.Fatalf("identity = %+v, %v", loaded, err)
	}
	if pki.Fingerprint(loaded.CA.Raw) != e.ca.Fingerprint() {
		t.Error("the stored CA is not the server's")
	}

	r := e.runAgent(dir, nil)
	e.wantPresence(id, true, 5*time.Second)
	if !e.gw.Online(id) {
		t.Error("the gateway does not list the running agent as online")
	}
	r.stop()
	if err := r.wait(t, 5*time.Second); err != nil {
		t.Errorf("a requested stop returned %v", err)
	}
	e.wantPresence(id, false, 5*time.Second)
}

func TestAGT1_TokenIsSingleUseAndIdentityIsNotOverwritten(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	token := e.token()
	if _, err := enroll.Do(context.Background(), e.enrollReq(dir, token)); err != nil {
		t.Fatal(err)
	}

	// Without --force an existing identity is kept, even with a fresh token.
	_, err := enroll.Do(context.Background(), e.enrollReq(dir, e.token()))
	if errcode.CodeOf(err) != errcode.AGTEnr001 {
		t.Errorf("second enrolment = %v, want %s", err, errcode.AGTEnr001)
	}

	// The spent token is refused, and the refusal never echoes it.
	forced := e.enrollReq(dir, token)
	forced.Force = true
	_, err = enroll.Do(context.Background(), forced)
	if errcode.CodeOf(err) != errcode.AGTEnr002 || strings.Contains(err.Error(), token) {
		t.Errorf("reused token = %v", err)
	}
	if _, err := identity.Load(dir); err != nil {
		t.Errorf("a failed forced enrolment damaged the existing identity: %v", err)
	}

	forced.Token = e.token()
	if _, err := enroll.Do(context.Background(), forced); err != nil {
		t.Errorf("forced enrolment with a fresh token: %v", err)
	}
}

func TestAGT3_AgentRefusesAGatewayThatIsNotTheOneInItsToken(t *testing.T) {
	e := newEnv(t)
	parts := strings.Split(e.token(), ".")
	other, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts[2] = other.Fingerprint() // the token now pins a different CA, as if a man-in-the-middle held the gateway
	dir := t.TempDir()

	_, err = enroll.Do(context.Background(), e.enrollReq(dir, strings.Join(parts, ".")))
	if errcode.CodeOf(err) != errcode.AGTEnr003 {
		t.Fatalf("got %v, want %s", err, errcode.AGTEnr003)
	}
	if identity.Exists(dir) {
		t.Error("an identity was written after the gateway failed verification")
	}
	if n := e.tokensSpent(); n != 0 {
		t.Errorf("%d tokens spent: the secret reached a server the agent did not trust", n)
	}
}

func (e *env) tokensSpent() int {
	e.t.Helper()
	var n int
	e.rawDB(func(db *sql.DB) {
		_ = db.QueryRow(`SELECT COUNT(*) FROM enrollment_tokens WHERE used_at IS NOT NULL`).Scan(&n)
	})
	return n
}

func (e *env) rawDB(f func(*sql.DB)) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	f(db)
}

func TestAGT5_AgentReconnectsAfterTheServerRestarts(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	id := e.enrollAgent(dir)
	r := e.runAgent(dir, nil)
	e.wantPresence(id, true, 5*time.Second)

	e.stopGW()
	<-e.gwStoped
	e.wantPresence(id, false, 5*time.Second)

	// The server comes back on the same address; the agent finds it without help.
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = gateway.Listen(e.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	gw2, err := gateway.New(context.Background(), gateway.Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Repo: e.db, Enroller: e.pki, Renewer: e.pki, CA: e.ca,
		ServerCert: e.ca.ServerCertificates([]string{"localhost", "127.0.0.1"}).GetCertificate, Heartbeat: beat,
		OnPresence: func(id string, online bool) { e.events <- presence{id, online} },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = gw2.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })

	e.wantPresence(id, true, 10*time.Second)
	r.stop()
	_ = r.wait(t, 5*time.Second)
}

func TestAGT4_CertificateRenewalRotatesTheKey(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	id := e.enrollAgent(dir)
	before, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	baseAudit, _ := e.db.VerifyAuditChain(context.Background())

	renewed := false
	r := e.runAgent(dir, func(c *run.Config) {
		c.RenewAt = func(*identity.Identity) time.Time {
			if !renewed {
				renewed = true
				return time.Now() // due immediately, once
			}
			return time.Now().Add(time.Hour)
		}
	})
	defer r.stop()
	e.wantPresence(id, true, 5*time.Second)

	var after *identity.Identity
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if got, err := identity.Load(dir); err == nil && got.Leaf.SerialNumber.Cmp(before.Leaf.SerialNumber) != 0 {
			after = got
			break
		}
	}
	if after == nil {
		t.Fatal("the certificate was not renewed")
	}
	if after.AgentID != id || after.Leaf.Subject.CommonName != id {
		t.Errorf("renewed certificate names %q, want agent %s", after.Leaf.Subject.CommonName, id)
	}
	if string(after.Leaf.RawSubjectPublicKeyInfo) == string(before.Leaf.RawSubjectPublicKeyInfo) {
		t.Error("renewal kept the old key")
	}
	if _, err := after.Leaf.Verify(x509.VerifyOptions{Roots: e.ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("renewed certificate does not verify: %v", err)
	}

	var certs int
	var current string
	e.rawDB(func(db *sql.DB) {
		_ = db.QueryRow(`SELECT COUNT(*) FROM agent_certs WHERE agent_id = ?`, id).Scan(&certs)
		_ = db.QueryRow(`SELECT cert_serial FROM agents WHERE id = ?`, id).Scan(&current)
	})
	if certs != 2 || current != after.Leaf.SerialNumber.Text(16) {
		t.Errorf("%d certificates on record, current %s; want 2 with the new one current", certs, current)
	}
	if n, _ := e.db.VerifyAuditChain(context.Background()); n != baseAudit+1 {
		t.Errorf("renewal wrote %d audit entries, want 1", n-baseAudit)
	}

	// The renewed identity connects on the next start.
	r.stop()
	_ = r.wait(t, 5*time.Second)
	e.wantPresence(id, false, 5*time.Second)
	r2 := e.runAgent(dir, nil)
	defer r2.stop()
	e.wantPresence(id, true, 5*time.Second)
}

func TestAGT4_RevocationDeniesEveryCertificateTheAgentEverHad(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	id := e.enrollAgent(dir)
	old, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	renewed := false
	r := e.runAgent(dir, func(c *run.Config) {
		c.RenewAt = func(*identity.Identity) time.Time {
			if !renewed {
				renewed = true
				return time.Now()
			}
			return time.Now().Add(time.Hour)
		}
	})
	e.wantPresence(id, true, 5*time.Second)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if cur, err := identity.Load(dir); err == nil && cur.Leaf.SerialNumber.Cmp(old.Leaf.SerialNumber) != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not renewed")
		}
	}

	if err := e.gw.Revoke(context.Background(), gateway.Actor{UserID: "01ADMIN"}, id); err != nil {
		t.Fatal(err)
	}
	err = r.wait(t, 10*time.Second)
	if errcode.CodeOf(err) != errcode.AGTRev001 {
		t.Fatalf("a revoked agent returned %v, want %s so systemd stops restarting it", err, errcode.AGTRev001)
	}

	// Both the pre-renewal certificate and the renewed one are refused at the handshake.
	for name, cert := range map[string]tls.Certificate{"renewed": mustLoad(t, dir).Cert, "pre-renewal": old.Cert} {
		stream, err := agentv1.NewAgentGatewayClient(e.dial(e.ca.Pool(), cert)).Connect(context.Background())
		if err == nil {
			_, err = stream.Recv()
		}
		if err == nil {
			t.Errorf("the %s certificate of a revoked agent was accepted", name)
		}
	}

	// Restarting the agent does not hammer the server forever: repeated rejections end the loop.
	r2 := e.runAgent(dir, nil)
	if err := r2.wait(t, 15*time.Second); errcode.CodeOf(err) != errcode.AGTRev001 {
		t.Errorf("restarted revoked agent returned %v, want %s", err, errcode.AGTRev001)
	}
}

func mustLoad(t *testing.T, dir string) *identity.Identity {
	t.Helper()
	id, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestExpiredCertificateIsFatalNotRetried(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	e.enrollAgent(dir)

	r := e.runAgent(dir, func(c *run.Config) { c.Now = func() time.Time { return time.Now().Add(48 * time.Hour) } })
	if err := r.wait(t, 5*time.Second); errcode.CodeOf(err) != errcode.AGTID002 {
		t.Errorf("got %v, want %s", err, errcode.AGTID002)
	}
}

func TestMissingIdentityIsFatal(t *testing.T) {
	e := newEnv(t)
	r := e.runAgent(t.TempDir(), nil)
	if err := r.wait(t, 5*time.Second); errcode.CodeOf(err) != errcode.AGTID001 {
		t.Errorf("got %v, want %s", err, errcode.AGTID001)
	}
}

func TestIdentityFilesStayPrivate(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(t.TempDir(), "state")
	e.enrollAgent(dir)
	for _, f := range []string{"agent.pem", "agent.json"} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode = %v, %v; group and others must have no access", f, info.Mode().Perm(), err)
		}
	}
}
