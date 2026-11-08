// SPDX-License-Identifier: AGPL-3.0-only

// Package pki runs the internal certificate authority that identifies agents,
// and the single-use enrolment tokens that let an agent obtain its first
// certificate.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const (
	caValidity = 10 * 365 * 24 * time.Hour
	// Issued certificates start slightly in the past so a host with a small clock lag still accepts them.
	clockSkew = time.Minute
)

// CA signs agent client certificates. Its key never leaves the data directory.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// LoadOrCreateCA reads <dir>/ca.crt and ca.key, creating a new CA on first start.
func LoadOrCreateCA(dir string, now time.Time) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "create pki directory", err)
	}
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath) //nolint:gosec // fixed name inside the data directory
	keyPEM, keyErr := os.ReadFile(keyPath)    //nolint:gosec // fixed name inside the data directory
	switch {
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		return createCA(certPath, keyPath, now)
	case certErr != nil:
		return nil, errcode.Wrap(errcode.GWCA001, "read ca.crt", certErr)
	case keyErr != nil:
		return nil, errcode.Wrap(errcode.GWCA001, "read ca.key", keyErr)
	}
	return parseCA(certPEM, keyPEM, now)
}

func createCA(certPath, keyPath string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "generate CA key", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "generate CA serial", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Nux Deck agent CA", Organization: []string{"Nux Deck"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "self-sign CA certificate", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "encode CA key", err)
	}
	// Key first: a crash between the two writes leaves an orphan key, which the next start refuses
	// rather than silently replacing a CA that agents already trust.
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "write ca.key", err)
	}
	if err := writeNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil { //nolint:gosec // a public certificate
		return nil, errcode.Wrap(errcode.GWCA001, "write ca.crt", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "parse new CA certificate", err)
	}
	return &CA{cert: cert, key: key}, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // path is fixed inside the data directory
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func parseCA(certPEM, keyPEM []byte, now time.Time) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errcode.New(errcode.GWCA001, "ca.crt holds no certificate")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "parse ca.crt", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errcode.New(errcode.GWCA001, "ca.key holds no key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCA001, "parse ca.key", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errcode.New(errcode.GWCA001, "ca.key is not an ECDSA key")
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errcode.New(errcode.GWCA001, "ca.crt is not a CA certificate for ca.key")
	}
	if now.After(cert.NotAfter) {
		return nil, errcode.New(errcode.GWCA001, "the CA certificate expired on %s", cert.NotAfter.Format(time.DateOnly))
	}
	return &CA{cert: cert, key: key}, nil
}

// Fingerprint is the hex SHA-256 of the CA certificate. Enrolment tokens carry it
// so an agent can pin the server before sending any secret.
func (c *CA) Fingerprint() string { return Fingerprint(c.cert.Raw) }

// Fingerprint returns the hex SHA-256 of a DER certificate.
func Fingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// CertDER is the CA certificate agents trust.
func (c *CA) CertDER() []byte { return c.cert.Raw }

// Pool returns a pool holding only this CA, for verifying client certificates.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Issued describes a freshly signed agent certificate.
type Issued struct {
	DER       []byte
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
}

// AgentURI is the URI SAN that names an agent in its certificate.
func AgentURI(agentID string) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: "nuxdeck:agent:" + agentID}
}

// Sign issues a client certificate for agentID valid for ttl. Only the public key
// is taken from the request: the subject and names are always the server's.
func (c *CA) Sign(csrDER []byte, agentID string, now time.Time, ttl time.Duration) (Issued, error) {
	pub, err := checkCSR(csrDER)
	if err != nil {
		return Issued{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return Issued{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID},
		URIs:         []*url.URL{AgentURI(agentID)},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return Issued{}, fmt.Errorf("sign agent certificate: %w", err)
	}
	return Issued{DER: der, Serial: serial.Text(16), NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}, nil
}

// checkCSR accepts only a self-consistent request carrying an ECDSA P-256 or P-384 key.
func checkCSR(der []byte) (crypto.PublicKey, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errcode.Wrap(errcode.GWCSR001, "parse request", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errcode.Wrap(errcode.GWCSR001, "request signature", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || (pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384()) {
		return nil, errcode.New(errcode.GWCSR001, "key must be ECDSA P-256 or P-384")
	}
	return pub, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// AgentIDFromCert returns the agent ID a certificate issued by Sign names.
func AgentIDFromCert(cert *x509.Certificate) (string, bool) {
	const prefix = "nuxdeck:agent:"
	for _, u := range cert.URIs {
		if id, ok := strings.CutPrefix(u.Opaque, prefix); ok && u.Scheme == "urn" && id != "" && id == cert.Subject.CommonName {
			return id, true
		}
	}
	return "", false
}
