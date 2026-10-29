// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

func TestBackupAndRestoreCommands(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "data")
	s, err := store.Open(ctx, dataDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("a passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"NUXD_DATA_DIR": dataDir}
	getenv := func(k string) string { return env[k] }
	archive := filepath.Join(t.TempDir(), "state.nuxbak")

	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"backup", "--out", archive, "--passphrase-file", passFile}, &out, &errOut, getenv); code != 0 {
		t.Fatalf("backup exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "encrypted=true") {
		t.Fatalf("backup output = %q", out.String())
	}

	target := filepath.Join(t.TempDir(), "restored")
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"restore", "--in", archive, "--data-dir", target, "--passphrase-file", passFile}, &out, &errOut, getenv); code != 0 {
		t.Fatalf("restore exit %d: %s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(target, "nux.db")); err != nil {
		t.Fatalf("restored database missing: %v", err)
	}
}

func TestBackupRequiresExplicitEncryptionChoice(t *testing.T) {
	var out, errOut bytes.Buffer
	getenv := func(string) string { return "" }
	out.Reset()
	errOut.Reset()
	// Neither --passphrase-file nor --unencrypted: refused rather than silently writing plaintext.
	if code := run(context.Background(), []string{"backup", "--out", filepath.Join(t.TempDir(), "x")}, &out, &errOut, getenv); code != 2 {
		t.Fatalf("exit %d, want 2; stderr %q", code, errOut.String())
	}
}
