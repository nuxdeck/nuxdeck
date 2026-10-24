// SPDX-License-Identifier: AGPL-3.0-only

// Package tlsutil provides nuxd's server certificate: a supplied pair, or a
// self-signed one generated on first start and renewed before it expires.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const (
	validity    = 365 * 24 * time.Hour
	renewWindow = 30 * 24 * time.Hour
)

// Options selects and, when needed, creates the certificate.
type Options struct {
	// CertFile and KeyFile, when set, are used as-is.
	CertFile, KeyFile string
	// DataDir holds the generated pair in its tls subdirectory.
	DataDir string
	// Hostnames are extra DNS names or IP addresses for the self-signed
	// certificate; localhost and the loopback addresses are always included.
	Hostnames []string
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time
}

// Certificate returns the certificate nuxd should serve.
func Certificate(o Options) (tls.Certificate, error) {
	if o.CertFile != "" {
		c, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return tls.Certificate{}, errcode.Wrap(errcode.SRVIO002, "load supplied certificate", err)
		}
		return c, nil
	}

	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	dir := filepath.Join(o.DataDir, "tls")
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")

	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && usable(c, o.Hostnames, now()) {
		return c, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, errcode.Wrap(errcode.SRVIO002, "create tls directory", err)
	}
	certPEM, keyPEM, err := selfSigned(o.Hostnames, now())
	if err != nil {
		return tls.Certificate{}, errcode.Wrap(errcode.SRVIO002, "generate self-signed certificate", err)
	}
	// Key first: a crash between the writes leaves a pair that fails to load and is regenerated.
	if err := writeFile(keyPath, keyPEM); err != nil {
		return tls.Certificate{}, errcode.Wrap(errcode.SRVIO002, "write private key", err)
	}
	if err := writeFile(certPath, certPEM); err != nil {
		return tls.Certificate{}, errcode.Wrap(errcode.SRVIO002, "write certificate", err)
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, errcode.Wrap(errcode.SRVIO002, "load generated certificate", err)
	}
	return c, nil
}

// usable reports whether an existing generated certificate can keep serving.
func usable(c tls.Certificate, hostnames []string, now time.Time) bool {
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || now.Add(renewWindow).After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return false
	}
	for _, h := range hostnames {
		if leaf.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

func selfSigned(hostnames []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nuxd", Organization: []string{"Nux Deck"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	for _, h := range slices.Compact(slices.Sorted(slices.Values(hostnames))) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// writeFile replaces path atomically with mode 0600.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer func() {
		if _, err := os.Stat(tmp.Name()); !errors.Is(err, fs.ErrNotExist) {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
