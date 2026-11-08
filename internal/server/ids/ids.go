// SPDX-License-Identifier: AGPL-3.0-only

// Package ids generates ULIDs: 128-bit identifiers that sort by creation time,
// written as 26 Crockford base32 characters.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// last holds the previous New result so that IDs created within one
// millisecond still sort in creation order, as the ULID spec requires.
var last struct {
	mu sync.Mutex
	ms int64
	b  [16]byte
}

// New returns a ULID for the current time. IDs from one process are strictly increasing.
func New() (string, error) {
	now := time.Now().UnixMilli()
	last.mu.Lock()
	defer last.mu.Unlock()
	if now <= last.ms {
		now = last.ms // a clock step back must not reorder IDs
		if !increment(last.b[6:]) {
			now++ // 80-bit counter exhausted; unreachable in practice
			if err := fill(&last.b, now); err != nil {
				return "", err
			}
			last.ms = now
		}
	} else if err := fill(&last.b, now); err != nil {
		return "", err
	} else {
		last.ms = now
	}
	return encode(last.b), nil
}

func increment(b []byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return true
		}
	}
	return false
}

func fill(b *[16]byte, ms int64) error {
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(ms)) //nolint:gosec // milliseconds since the epoch are positive
	copy(b[:6], t[2:])
	if _, err := rand.Read(b[6:]); err != nil {
		return fmt.Errorf("read random bytes: %w", err)
	}
	// Leave headroom so the counter cannot overflow within one millisecond.
	b[6] &= 0x7f
	return nil
}

// At returns a ULID for t.
func At(t time.Time) (string, error) {
	var b [16]byte
	if err := fill(&b, t.UnixMilli()); err != nil {
		return "", err
	}
	return encode(b), nil
}

func encode(b [16]byte) string {
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
	return string(out)
}
