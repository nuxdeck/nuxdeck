// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func tokenString(url string, fp []byte, secret int) string {
	return strings.Join([]string{"nuxtok1", base64.RawURLEncoding.EncodeToString([]byte(url)), hex.EncodeToString(fp), base64.RawURLEncoding.EncodeToString(make([]byte, secret))}, ".")
}

func TestParseToken(t *testing.T) {
	fp := make([]byte, sha256.Size)
	good := tokenString("https://nux.example.com:8444", fp, 32)
	tok, err := ParseToken("  " + good + "\n")
	if err != nil || tok.GatewayURL != "https://nux.example.com:8444" || tok.CAFingerprint != hex.EncodeToString(fp) || tok.Raw != good {
		t.Fatalf("ParseToken = %+v, %v", tok, err)
	}

	for name, s := range map[string]string{
		"empty":             "",
		"wrong version":     strings.Replace(good, "nuxtok1", "nuxtok2", 1),
		"http gateway":      tokenString("http://nux.example.com", fp, 32),
		"no host":           tokenString("https://", fp, 32),
		"short fingerprint": tokenString("https://nux.example.com", fp[:8], 32),
		"short secret":      tokenString("https://nux.example.com", fp, 8),
		"extra part":        good + ".x",
	} {
		_, err := ParseToken(s)
		if errcode.CodeOf(err) != errcode.AGTEnr002 {
			t.Errorf("%s: got %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "AAAA") {
			t.Errorf("%s: the error echoes the token", name)
		}
	}
}

func testPair(t *testing.T) (ca *x509.Certificate, certDER []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agent"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24*time.Hour - time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certDER, key
}

func TestSaveAndLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	ca, certDER, key := testPair(t)

	if Exists(dir) {
		t.Fatal("an empty directory holds no identity")
	}
	if _, err := Load(dir); errcode.CodeOf(err) != errcode.AGTID001 {
		t.Errorf("Load of nothing = %v, want %s", err, errcode.AGTID001)
	}
	if err := Save(dir, "01AGENT", "https://nux.example.com:8444", ca.Raw, certDER, key); err != nil {
		t.Fatal(err)
	}
	id, err := Load(dir)
	if err != nil || id.AgentID != "01AGENT" || id.GatewayURL != "https://nux.example.com:8444" || !Exists(dir) {
		t.Fatalf("Load = %+v, %v", id, err)
	}

	for name, wantMode := range map[string]os.FileMode{"agent.pem": 0o600, "agent.json": 0o600, "ca.crt": 0o644} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != wantMode {
			t.Errorf("%s mode = %v, %v; want %v", name, info.Mode().Perm(), err, wantMode)
		}
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("state directory mode = %v, want 0700", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3 {
		t.Errorf("state directory holds %d files, want exactly 3 (leftover temp files?)", len(entries))
	}

	if want := id.Leaf.NotBefore.Add(id.Leaf.NotAfter.Sub(id.Leaf.NotBefore) * 2 / 3); !id.RenewAt().Equal(want) {
		t.Errorf("RenewAt = %v, want %v", id.RenewAt(), want)
	}
}

func TestRenewalReplacesKeyAndCertificateTogether(t *testing.T) {
	dir := t.TempDir()
	ca, certDER, key := testPair(t)
	if err := Save(dir, "01AGENT", "https://nux.example.com", ca.Raw, certDER, key); err != nil {
		t.Fatal(err)
	}
	_, newCert, newKey := testPair(t)
	if err := SaveCertificate(dir, newCert, newKey); err != nil {
		t.Fatal(err)
	}
	id, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(id.Cert.Certificate[0]) != string(newCert) {
		t.Error("renewal did not replace the certificate")
	}
}

func TestLoadRejectsTamperedState(t *testing.T) {
	ca, certDER, key := testPair(t)
	otherCA, _, _ := testPair(t)

	cases := map[string]func(dir string){
		"CA swapped for another": func(dir string) {
			pemBytes := "-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(otherCA.Raw) + "\n-----END CERTIFICATE-----\n"
			_ = os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(pemBytes), 0o644) //nolint:gosec // test fixture
		},
		"missing key":      func(dir string) { _ = os.Remove(filepath.Join(dir, "agent.pem")) },
		"corrupt pair":     func(dir string) { _ = os.WriteFile(filepath.Join(dir, "agent.pem"), []byte("junk"), 0o600) },
		"corrupt metadata": func(dir string) { _ = os.WriteFile(filepath.Join(dir, "agent.json"), []byte("{"), 0o600) },
	}
	for name, damage := range cases {
		dir := t.TempDir()
		if err := Save(dir, "01AGENT", "https://nux.example.com", ca.Raw, certDER, key); err != nil {
			t.Fatal(err)
		}
		damage(dir)
		if _, err := Load(dir); errcode.CodeOf(err) != errcode.AGTID001 {
			t.Errorf("%s: Load = %v, want %s", name, err, errcode.AGTID001)
		}
	}
}
