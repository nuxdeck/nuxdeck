// SPDX-License-Identifier: Apache-2.0

// Package identity holds what an enrolled agent keeps on disk: its key, its
// certificate, the CA it trusts and the gateway it dials.
package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const (
	tokenPrefix = "nuxtok1"
	secretBytes = 32
)

// Token is a decoded enrolment token: nuxtok1.<gateway URL>.<CA fingerprint>.<secret>,
// each part base64url or hex, so no part contains a dot.
type Token struct {
	GatewayURL    string
	CAFingerprint string // hex SHA-256 of the CA certificate
	// Raw is the whole token as the server expects it. Never log it.
	Raw string
}

// ParseToken decodes a token string. Errors never echo the input, which holds a secret.
func ParseToken(s string) (Token, error) {
	bad := func() (Token, error) {
		return Token{}, errcode.New(errcode.AGTEnr002, "the enrolment token is malformed; copy it again in full")
	}
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 4 || parts[0] != tokenPrefix {
		return bad()
	}
	rawURL, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return bad()
	}
	u, err := url.Parse(string(rawURL))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return bad()
	}
	if fp, err := hex.DecodeString(parts[2]); err != nil || len(fp) != sha256.Size {
		return bad()
	}
	if secret, err := base64.RawURLEncoding.DecodeString(parts[3]); err != nil || len(secret) != secretBytes {
		return bad()
	}
	return Token{GatewayURL: string(rawURL), CAFingerprint: parts[2], Raw: strings.TrimSpace(s)}, nil
}
