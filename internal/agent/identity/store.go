// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// File names inside the state directory. agent.json is written last on enrolment, so its
// presence marks a complete identity; agent.pem (certificate then key) is replaced in one
// rename on renewal, so the key and certificate can never be out of step.
const (
	metaFile = "agent.json"
	pairFile = "agent.pem"
	caFile   = "ca.crt"
)

type meta struct {
	AgentID       string `json:"agent_id"`
	GatewayURL    string `json:"gateway_url"`
	CAFingerprint string `json:"ca_fingerprint"`
}

// Identity is an enrolled agent's credentials.
type Identity struct {
	AgentID       string
	GatewayURL    string
	CAFingerprint string
	CA            *x509.Certificate
	Cert          tls.Certificate
	Leaf          *x509.Certificate
}

// RenewAt is when the agent should ask for a new certificate: two thirds into its life
// (16 of 24 hours), so a stolen certificate is useful for at most a day.
func (i *Identity) RenewAt() time.Time {
	life := i.Leaf.NotAfter.Sub(i.Leaf.NotBefore)
	return i.Leaf.NotBefore.Add(life * 2 / 3)
}

// Exists reports whether dir holds a complete identity.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, metaFile))
	return err == nil
}

// Save writes a fresh identity. It creates dir (0700) and orders the writes so a crash
// leaves either the old identity or no identity, never half of a new one.
func Save(dir, agentID, gatewayURL string, caDER, certDER []byte, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errcode.Wrap(errcode.AGTID001, "create state directory", err)
	}
	if err := os.Remove(filepath.Join(dir, metaFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errcode.Wrap(errcode.AGTID001, "clear old identity", err)
	}
	if err := writeAtomic(filepath.Join(dir, caFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil { //nolint:gosec // a public certificate
		return errcode.Wrap(errcode.AGTID001, "write ca.crt", err)
	}
	if err := SaveCertificate(dir, certDER, key); err != nil {
		return err
	}
	body, err := json.Marshal(meta{AgentID: agentID, GatewayURL: gatewayURL, CAFingerprint: hex.EncodeToString(fingerprint(caDER))})
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, metaFile), body, 0o600); err != nil {
		return errcode.Wrap(errcode.AGTID001, "write agent.json", err)
	}
	return nil
}

// SaveCertificate replaces the agent's certificate and key together, atomically.
func SaveCertificate(dir string, certDER []byte, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errcode.Wrap(errcode.AGTID001, "encode key", err)
	}
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	if err := writeAtomic(filepath.Join(dir, pairFile), data, 0o600); err != nil {
		return errcode.Wrap(errcode.AGTID001, "write agent.pem", err)
	}
	return nil
}

// Load reads the identity and checks that its parts belong together.
func Load(dir string) (*Identity, error) {
	bad := func(what string, err error) (*Identity, error) {
		if err == nil {
			err = errors.New("unexpected content")
		}
		return nil, errcode.Wrap(errcode.AGTID001, what, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, metaFile)) //nolint:gosec // fixed name inside the state directory
	if err != nil {
		return bad("read agent.json (is this host enrolled?)", err)
	}
	var m meta
	if err := json.Unmarshal(body, &m); err != nil || m.AgentID == "" || m.GatewayURL == "" {
		return bad("parse agent.json", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(dir, caFile)) //nolint:gosec // fixed name inside the state directory
	if err != nil {
		return bad("read ca.crt", err)
	}
	cb, _ := pem.Decode(caPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return bad("parse ca.crt", nil)
	}
	ca, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return bad("parse ca.crt", err)
	}
	if hex.EncodeToString(fingerprint(ca.Raw)) != m.CAFingerprint {
		return bad("ca.crt does not match the fingerprint the agent enrolled with", nil)
	}

	pair, err := os.ReadFile(filepath.Join(dir, pairFile)) //nolint:gosec // fixed name inside the state directory
	if err != nil {
		return bad("read agent.pem", err)
	}
	cert, err := tls.X509KeyPair(pair, pair)
	if err != nil {
		return bad("parse agent.pem", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return bad("parse agent certificate", err)
	}
	return &Identity{AgentID: m.AgentID, GatewayURL: m.GatewayURL, CAFingerprint: m.CAFingerprint, CA: ca, Cert: cert, Leaf: leaf}, nil
}

func fingerprint(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}

// writeAtomic writes through a temporary file in the same directory, syncs it and renames it into place.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the state directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
