// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	serverCertValidity = 90 * 24 * time.Hour
	serverCertRenewAt  = 30 * 24 * time.Hour
)

// ServerCerts supplies the gateway's TLS certificate. It is signed by the agent
// CA, so an agent that pinned the CA fingerprint from its token can verify the
// server (AGT-3). The key is generated in memory and replaced before expiry.
type ServerCerts struct {
	ca    *CA
	hosts []string
	// Now supplies the clock; nil means time.Now. Tests set it.
	Now func() time.Time

	mu     sync.Mutex
	cached *tls.Certificate
	expiry time.Time
}

// ServerCertificates returns a source for a certificate valid for hosts (DNS names or IPs).
func (c *CA) ServerCertificates(hosts []string) *ServerCerts {
	return &ServerCerts{ca: c, hosts: hosts}
}

// GetCertificate fits tls.Config.GetCertificate.
func (s *ServerCerts) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && s.expiry.Sub(now) > serverCertRenewAt {
		return s.cached, nil
	}
	cert, expiry, err := s.issue(now)
	if err != nil {
		return nil, err
	}
	s.cached, s.expiry = cert, expiry
	return cert, nil
}

func (s *ServerCerts) issue(now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate gateway key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nuxd gateway"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range s.hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.cert, &key.PublicKey, s.ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign gateway certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, tmpl.NotAfter, nil
}
