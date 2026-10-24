// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SetupToken guards first-run setup. Without it, whoever reaches a fresh
// server first could claim the administrator account. The token lives in a
// 0600 file in the data directory and is never logged; `nuxd setup-token`
// prints it for the operator.
type SetupToken struct {
	path string
}

// NewSetupToken points at the token file inside dataDir.
func NewSetupToken(dataDir string) *SetupToken {
	return &SetupToken{path: filepath.Join(dataDir, "setup-token")}
}

// Path is where the token file lives.
func (t *SetupToken) Path() string { return t.path }

// Ensure creates the token if the file does not exist yet.
func (t *SetupToken) Ensure() error {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate setup token: %w", err)
	}
	f, err := os.OpenFile(t.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed file name inside the data directory
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create setup token: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(raw) + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("write setup token: %w", err)
	}
	return f.Close()
}

// Read returns the current token.
func (t *SetupToken) Read() (string, error) {
	b, err := os.ReadFile(t.path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Verify compares candidate with the token in constant time. It is false when no token exists.
func (t *SetupToken) Verify(candidate string) bool {
	want, err := t.Read()
	if err != nil || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(candidate)), []byte(want)) == 1
}

// Remove deletes the token once setup is complete.
func (t *SetupToken) Remove() error {
	if err := os.Remove(t.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
