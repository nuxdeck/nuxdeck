// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// tokenPrefix versions the wire format: nuxtok1.<server URL>.<CA fingerprint>.<secret>,
// each part base64url or hex so no part contains a dot.
const (
	tokenPrefix = "nuxtok1"
	secretBytes = 32
)

// Token is the decoded form of an enrolment token string.
type Token struct {
	ServerURL     string
	CAFingerprint string
	Secret        string
}

// NewToken draws a fresh secret from the system CSPRNG.
func NewToken(serverURL, caFingerprint string) (Token, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, fmt.Errorf("read random bytes: %w", err)
	}
	return Token{ServerURL: serverURL, CAFingerprint: caFingerprint, Secret: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// String renders the token. It is shown once and never stored.
func (t Token) String() string {
	return strings.Join([]string{
		tokenPrefix,
		base64.RawURLEncoding.EncodeToString([]byte(t.ServerURL)),
		t.CAFingerprint,
		t.Secret,
	}, ".")
}

// Hash is what the server stores: the SHA-256 of the secret, in hex.
func (t Token) Hash() string {
	sum := sha256.Sum256([]byte(t.Secret))
	return hex.EncodeToString(sum[:])
}

// ParseToken decodes and validates the shape of a token string.
func ParseToken(s string) (Token, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 || parts[0] != tokenPrefix {
		return Token{}, errcode.New(errcode.GWTok001, "malformed token")
	}
	rawURL, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Token{}, errcode.New(errcode.GWTok001, "malformed token")
	}
	u, err := url.Parse(string(rawURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Token{}, errcode.New(errcode.GWTok001, "malformed token")
	}
	fp, err := hex.DecodeString(parts[2])
	if err != nil || len(fp) != sha256.Size {
		return Token{}, errcode.New(errcode.GWTok001, "malformed token")
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(secret) != secretBytes {
		return Token{}, errcode.New(errcode.GWTok001, "malformed token")
	}
	return Token{ServerURL: string(rawURL), CAFingerprint: parts[2], Secret: parts[3]}, nil
}
