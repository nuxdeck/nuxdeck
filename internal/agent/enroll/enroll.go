// SPDX-License-Identifier: Apache-2.0

// Package enroll turns a single-use token into an agent identity.
package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nuxdeck/nuxdeck/internal/agent/identity"
	"github.com/nuxdeck/nuxdeck/internal/agent/link"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const timeout = 30 * time.Second

// Request describes this host and what to enrol with.
type Request struct {
	StateDir string
	Token    string
	// Force replaces an existing identity.
	Force    bool
	Version  string
	Hostname string
	OS       string
	Arch     string
}

// Do enrols the host and writes the identity to the state directory. The private key
// is generated here and only a certificate request leaves the host.
func Do(ctx context.Context, r Request) (agentID string, err error) {
	tok, err := identity.ParseToken(r.Token)
	if err != nil {
		return "", err
	}
	if identity.Exists(r.StateDir) && !r.Force {
		return "", errcode.New(errcode.AGTEnr001, "%s already holds an identity", r.StateDir)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", fmt.Errorf("create certificate request: %w", err)
	}

	conn, err := link.Pinned(tok)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := agentv1.NewAgentGatewayClient(conn).Enroll(ctx, &agentv1.EnrollRequest{
		Token: tok.Raw, CsrDer: csr, AgentVersion: r.Version, Hostname: r.Hostname, Os: r.OS, Arch: r.Arch,
	})
	if err != nil {
		return "", classify(err)
	}

	if err := identity.Save(r.StateDir, res.GetAgentId(), tok.GatewayURL, res.GetCaCertDer(), res.GetCertDer(), key); err != nil {
		return "", err
	}
	// Load back what was written, so a mismatch (a CA that is not the pinned one) is caught now, not at first connect.
	if _, err := identity.Load(r.StateDir); err != nil {
		return "", err
	}
	return res.GetAgentId(), nil
}

// classify turns a transport or server error into a coded one, keeping the server's own
// code for the user without ever echoing the token.
func classify(err error) error {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unavailable {
		return errcode.New(errcode.AGTEnr002, "the server refused enrolment (%s: %s)", st.Code(), st.Message())
	}
	if strings.Contains(err.Error(), "CA fingerprint") || strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "CA certificate") {
		return errcode.Wrap(errcode.AGTEnr003, "verify gateway", errors.New(err.Error()))
	}
	return errcode.Wrap(errcode.AGTEnr002, "reach the gateway", err)
}
