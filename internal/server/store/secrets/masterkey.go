// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// EnvMasterKey names the environment variable that carries the master key (base64, 32 bytes). The key is never
// part of config.Config, so it cannot reach a log line through the settings.
const EnvMasterKey = "NUXD_MASTER_KEY"

// GeneratedKeyFile is the name of the key nuxd creates in the data directory.
const GeneratedKeyFile = "master.key"

// LoadMasterKey resolves the master key from, in this order of exclusivity: the
// NUXD_MASTER_KEY variable, the configured keyFile, or <dataDir>/master.key, which is
// created (mode 0600) when it does not exist. Setting both the variable and keyFile is an
// error rather than a silent precedence. created reports a freshly generated key.
//
// Keys are 32 random bytes, base64-encoded (standard alphabet), surrounded by optional
// whitespace. A key file must be a regular file with no group or other permission bits.
// The key is never logged and never appears in error text.
func LoadMasterKey(dataDir, keyFile string, getenv func(string) string) (key []byte, created bool, err error) {
	if env := strings.TrimSpace(getenv(EnvMasterKey)); env != "" {
		if keyFile != "" {
			return nil, false, errcode.New(errcode.SRVSec001, "%s and secrets.master_key_file are both set; use only one", EnvMasterKey)
		}
		key, err = decodeKey([]byte(env))
		if err != nil {
			return nil, false, errcode.New(errcode.SRVSec001, "%s: %v", EnvMasterKey, err)
		}
		return key, false, nil
	}

	if keyFile != "" {
		key, err = readKeyFile(keyFile)
		return key, false, err
	}

	path := filepath.Join(dataDir, GeneratedKeyFile)
	key, err = readKeyFile(path)
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	key, err = generateKeyFile(path)
	if errors.Is(err, fs.ErrExist) { // another process won the race; use its key
		key, err = readKeyFile(path)
		return key, false, err
	}
	return key, err == nil, err
}

func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied key path
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("master key file %s: %w", path, fs.ErrNotExist)
		}
		return nil, errcode.Wrap(errcode.SRVSec001, "open master key file "+path, err)
	}
	defer func() { _ = f.Close() }()

	// Inspect the open handle, not the path, so the file cannot change between check and read.
	info, err := f.Stat()
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVSec001, "inspect master key file "+path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, errcode.New(errcode.SRVSec001, "master key file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errcode.New(errcode.SRVSec001, "master key file %s has mode %04o; it must not be accessible to group or others (chmod 600)", path, info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1024))
	defer clear(raw)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVSec001, "read master key file "+path, err)
	}
	key, err := decodeKey(raw)
	if err != nil {
		return nil, errcode.New(errcode.SRVSec001, "master key file %s: %v", path, err)
	}
	return key, nil
}

// generateKeyFile creates path exclusively with mode 0600 and fills it with a new key.
func generateKeyFile(path string) (key []byte, err error) {
	key = make([]byte, KeyLen)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return nil, errcode.Wrap(errcode.SRVSec001, "generate master key", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path is under the data directory
	if err != nil {
		clear(key)
		if errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		return nil, errcode.Wrap(errcode.SRVSec001, "create master key file "+path, err)
	}
	encoded := base64.StdEncoding.AppendEncode(nil, key)
	encoded = append(encoded, '\n')
	defer clear(encoded)
	_, werr := f.Write(encoded)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		clear(key)
		_ = os.Remove(path) // a partial key file would lock the database out on the next start
		return nil, errcode.Wrap(errcode.SRVSec001, "write master key file "+path, werr)
	}
	return key, nil
}

func decodeKey(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	key, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, errors.New("not valid base64")
	}
	if len(key) != KeyLen {
		clear(key)
		return nil, fmt.Errorf("must decode to %d bytes, got %d", KeyLen, len(key))
	}
	return key, nil
}
