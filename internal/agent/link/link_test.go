// SPDX-License-Identifier: Apache-2.0

package link

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type pki struct {
	caDER   []byte
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	fingerp []byte
}

func newCA(t *testing.T) pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(der)
	return pki{caDER: der, ca: ca, caKey: key, fingerp: sum[:]}
}

func (p pki) leaf(t *testing.T, names []string, eku x509.ExtKeyUsage, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gw"}, DNSNames: names, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestAGT3_VerifyPinned(t *testing.T) {
	good, other := newCA(t), newCA(t)
	future := time.Now().Add(time.Hour)
	leaf := good.leaf(t, []string{"nux.example.com"}, x509.ExtKeyUsageServerAuth, future)

	state := func(certs ...*x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: certs}
	}
	tests := []struct {
		name string
		cs   tls.ConnectionState
		host string
		pin  []byte
		ok   bool
	}{
		{"chain with the pinned CA", state(leaf, good.ca), "nux.example.com", good.fingerp, true},
		{"CA sent first is not special", state(leaf, other.ca, good.ca), "nux.example.com", good.fingerp, true},
		{"wrong pin", state(leaf, good.ca), "nux.example.com", other.fingerp, false},
		{"server forgot to send the CA", state(leaf), "nux.example.com", good.fingerp, false},
		{"attacker CA with the right name", state(other.leaf(t, []string{"nux.example.com"}, x509.ExtKeyUsageServerAuth, future), other.ca), "nux.example.com", good.fingerp, false},
		{"attacker leaf claiming the pinned CA", state(other.leaf(t, []string{"nux.example.com"}, x509.ExtKeyUsageServerAuth, future), good.ca), "nux.example.com", good.fingerp, false},
		{"wrong host name", state(leaf, good.ca), "evil.example.com", good.fingerp, false},
		{"client certificate used as server", state(good.leaf(t, []string{"nux.example.com"}, x509.ExtKeyUsageClientAuth, future), good.ca), "nux.example.com", good.fingerp, false},
		{"expired leaf", state(good.leaf(t, []string{"nux.example.com"}, x509.ExtKeyUsageServerAuth, time.Now().Add(-time.Second)), good.ca), "nux.example.com", good.fingerp, false},
		{"leaf posing as the pinned CA", state(leaf, leaf), "nux.example.com", good.fingerp, false},
	}
	for _, tt := range tests {
		err := verifyPinned(tt.cs, tt.host, tt.pin)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestTarget(t *testing.T) {
	addr, host, err := Target("https://nux.example.com:8444")
	if err != nil || addr != "nux.example.com:8444" || host != "nux.example.com" {
		t.Errorf("Target = %q %q %v", addr, host, err)
	}
	if addr, _, _ := Target("https://nux.example.com"); addr != "nux.example.com:443" {
		t.Errorf("default port: %q", addr)
	}
	for _, bad := range []string{"http://x.example", "nux.example.com:8444", "https://", "://"} {
		if _, _, err := Target(bad); err == nil {
			t.Errorf("Target(%q) accepted", bad)
		}
	}
}
