// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16
	keyLen  = 32
	// maxConcurrentHashes bounds memory: each hash briefly needs memoryKiB.
	maxConcurrentHashes = 4
)

// Hasher hashes and verifies passwords with Argon2id, writing the standard PHC string.
type Hasher struct {
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
	slots       chan struct{}
}

// NewHasher uses 64 MiB, 3 passes and 2 lanes, above the OWASP minimum for Argon2id.
func NewHasher() *Hasher { return NewHasherWithParams(64*1024, 3, 2) }

// NewHasherWithParams exists so tests can use cheap parameters.
func NewHasherWithParams(memoryKiB, iterations uint32, parallelism uint8) *Hasher {
	return &Hasher{memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism, slots: make(chan struct{}, maxConcurrentHashes)}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.slots }

// Hash returns the PHC-encoded Argon2id hash of password with a fresh random salt.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.iterations, h.memoryKiB, h.parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.memoryKiB, h.iterations, h.parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches the encoded hash, in constant time for the comparison.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	var version int
	var memory, iterations uint32
	var parallelism uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("not an argon2id hash")
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, fmt.Errorf("bad argon2 parameters")
	}
	// Parameters come from our own database, but cap them so a corrupted row cannot exhaust memory.
	if memory == 0 || memory > 256*1024 || iterations == 0 || iterations > 10 || parallelism == 0 || parallelism > 16 {
		return false, fmt.Errorf("argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false, fmt.Errorf("bad argon2 salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, fmt.Errorf("bad argon2 key")
	}

	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want))) //nolint:gosec // length of a decoded hash, well below 2^32
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
