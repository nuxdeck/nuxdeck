// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const (
	tlsHandshakeTimeout = 10 * time.Second
	fingerprintPrefix   = "sha256:"
)

// trust describes how the server certificate is verified. The order is: a pin (the leaf
// certificate must hash to it), then a private CA file, then the system roots. Insecure
// disables verification entirely and is only for debugging.
type trust struct {
	CAFile   string
	Pin      string
	Insecure bool
}

func (t trust) transport() (*http.Transport, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // the minimum is TLS 1.2; verification is set below
	switch {
	case t.Insecure:
		tc.InsecureSkipVerify = true
	case t.Pin != "":
		want, err := parseFingerprint(t.Pin)
		if err != nil {
			return nil, err
		}
		// The pin replaces chain validation: a self-signed certificate is accepted only when it matches.
		tc.InsecureSkipVerify = true //nolint:gosec // VerifyPeerCertificate below enforces the pin
		tc.VerifyPeerCertificate = pinVerifier(want)
		// A resumed session skips VerifyPeerCertificate, so resumption is disabled for pinned connections.
		tc.SessionTicketsDisabled = true
	}
	if t.CAFile != "" {
		pool, err := loadCAs(t.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tc,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		ForceAttemptHTTP2:   true,
	}, nil
}

func pinVerifier(want [sha256.Size]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errcode.New(errcode.CLINet002, "the server sent no certificate")
		}
		got := sha256.Sum256(raw[0])
		if got != want {
			return errcode.New(errcode.CLINet002, "certificate fingerprint %s does not match the pin", formatFingerprint(got))
		}
		return nil
	}
}

func loadCAs(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-supplied CA bundle
	if err != nil {
		return nil, errcode.Wrap(errcode.CLICfg001, "read CA file "+path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errcode.New(errcode.CLIArg002, "CA file %s contains no PEM certificates", path)
	}
	return pool, nil
}

// parseFingerprint accepts sha256:HEX with optional colons between byte pairs, as printed by openssl.
func parseFingerprint(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	body, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(s)), fingerprintPrefix)
	if !ok {
		return out, errcode.New(errcode.CLIArg002, "pin must start with sha256:, got %q", s)
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(body, ":", ""))
	if err != nil || len(raw) != sha256.Size {
		return out, errcode.New(errcode.CLIArg002, "pin must be sha256 followed by 64 hex digits")
	}
	copy(out[:], raw)
	return out, nil
}

func formatFingerprint(sum [sha256.Size]byte) string {
	return fingerprintPrefix + hex.EncodeToString(sum[:])
}

// probeFingerprint performs a handshake without verification and returns the leaf fingerprint,
// so that login can show it to the user before anything is trusted.
func probeFingerprint(ctx context.Context, server *url.URL) (string, error) {
	port := server.Port()
	if port == "" {
		port = "443"
		if server.Scheme == "http" {
			port = "80"
		}
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: tlsHandshakeTimeout},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // read-only probe; nothing is sent
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server.Hostname(), port))
	if err != nil {
		return "", errcode.Wrap(errcode.CLINet001, "connect to "+server.Host, err)
	}
	defer func() { _ = conn.Close() }()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errcode.New(errcode.CLINet002, "the server sent no certificate")
	}
	return formatFingerprint(sha256.Sum256(state.PeerCertificates[0].Raw)), nil
}

// isUntrusted reports whether err is a certificate chain failure, the only case where
// trust-on-first-use is offered.
func isUntrusted(err error) bool {
	var verr *tls.CertificateVerificationError
	var uerr x509.UnknownAuthorityError
	return errors.As(err, &verr) || errors.As(err, &uerr)
}
