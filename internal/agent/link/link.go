// SPDX-License-Identifier: Apache-2.0

// Package link builds the agent's connections to the nuxd gateway. The agent only
// ever dials out (AGT-2).
package link

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/nuxdeck/nuxdeck/internal/agent/identity"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Target splits a gateway URL into the dial address and the name its certificate must carry.
func Target(gatewayURL string) (addr, host string, err error) {
	u, err := url.Parse(gatewayURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", "", fmt.Errorf("gateway URL must be https://host[:port], got %q", gatewayURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname() + ":" + port, u.Hostname(), nil
}

// Pinned dials the gateway before the agent has an identity. The server is trusted only if
// it presents a chain whose CA certificate has exactly the SHA-256 fingerprint carried in the
// enrolment token (AGT-3), so a man-in-the-middle cannot receive the token secret.
func Pinned(tok identity.Token) (*grpc.ClientConn, error) {
	addr, host, err := Target(tok.GatewayURL)
	if err != nil {
		return nil, errcode.Wrap(errcode.AGTEnr002, "token gateway", err)
	}
	want, err := hex.DecodeString(tok.CAFingerprint)
	if err != nil {
		return nil, errcode.Wrap(errcode.AGTEnr002, "token fingerprint", err)
	}
	conf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: host,
		// The standard verifier needs roots we do not have yet; VerifyConnection below does the
		// full verification against the pinned CA instead.
		InsecureSkipVerify: true, //nolint:gosec // replaced by verifyPinned
		VerifyConnection:   func(cs tls.ConnectionState) error { return verifyPinned(cs, host, want) },
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(conf)))
}

// verifyPinned accepts the server only if one certificate in its chain has the pinned
// fingerprint and the leaf validly chains to it for host.
func verifyPinned(cs tls.ConnectionState, host string, want []byte) error {
	if len(cs.PeerCertificates) < 2 {
		return errors.New("the gateway did not send its CA certificate")
	}
	leaf := cs.PeerCertificates[0]
	roots := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		sum := sha256.Sum256(c.Raw)
		if subtle.ConstantTimeCompare(sum[:], want) == 1 {
			roots.AddCert(c)
		}
	}
	if len(roots.Subjects()) == 0 { //nolint:staticcheck // only the count matters; no system roots are involved
		return errors.New("no certificate in the gateway's chain matches the CA fingerprint")
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

// Mutual dials the gateway with the agent's own certificate, trusting only the CA it enrolled with.
func Mutual(id *identity.Identity) (*grpc.ClientConn, error) {
	addr, host, err := Target(id.GatewayURL)
	if err != nil {
		return nil, errcode.Wrap(errcode.AGTID001, "gateway URL", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(id.CA)
	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: host, RootCAs: roots, Certificates: []tls.Certificate{id.Cert},
	})))
}
