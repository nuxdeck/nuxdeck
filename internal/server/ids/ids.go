// SPDX-License-Identifier: AGPL-3.0-only

// Package ids generates ULIDs: 128-bit identifiers that sort by creation time,
// written as 26 Crockford base32 characters.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a ULID for the current time.
func New() (string, error) {
	return At(time.Now())
}

// At returns a ULID for t.
func At(t time.Time) (string, error) {
	var b [16]byte
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(t.UnixMilli())) //nolint:gosec // milliseconds since the epoch are positive
	copy(b[:6], ms[2:])
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	// 128 bits are written as 26 groups of 5 bits, so the first group carries 2 padding zeros.
	out := make([]byte, 26)
	for i := range out {
		var v byte
		for j := 0; j < 5; j++ {
			bit := 5*i + j - 2
			v <<= 1
			if bit >= 0 && b[bit/8]&(0x80>>(bit%8)) != 0 {
				v |= 1
			}
		}
		out[i] = alphabet[v]
	}
	return string(out), nil
}
