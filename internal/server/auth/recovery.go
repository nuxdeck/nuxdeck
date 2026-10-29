// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const (
	recoveryCodeCount = 10
	recoveryAlphabet  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no look-alikes; 32 symbols divide 256 evenly
	recoveryHalfLen   = 5
)

// NewRecoveryCodes returns count one-time codes shown to the user once, and their hashes for storage.
func NewRecoveryCodes() (codes, hashes []string, err error) {
	for range recoveryCodeCount {
		raw := make([]byte, 2*recoveryHalfLen)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		var sb strings.Builder
		for i, b := range raw {
			if i == recoveryHalfLen {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(b)%len(recoveryAlphabet)])
		}
		codes = append(codes, sb.String())
		hashes = append(hashes, hashRecoveryCode(sb.String()))
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode makes entry forgiving: case, dashes and spaces do not matter.
func normalizeRecoveryCode(s string) string {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(s) != 2*recoveryHalfLen {
		return ""
	}
	return s
}

func hashRecoveryCode(code string) string {
	n := normalizeRecoveryCode(code)
	if n == "" {
		return ""
	}
	return hashToken("recovery:" + n)
}
