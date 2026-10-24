// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestOpenCreatesWALDatabaseAndMigrates(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "data")

	s, err := Open(ctx, dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("data dir mode = %o, want 700", perm)
	}

	var mode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q (err %v), want wal", mode, err)
	}
	var fk int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d (err %v), want 1", fk, err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v != 1 {
		t.Errorf("SchemaVersion = %d (err %v), want 1", v, err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		s, err := Open(ctx, dir, discard)
		if err != nil {
			t.Fatalf("open #%d: %v", i+1, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenUnusableDataDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), filepath.Join(file, "sub"), discard)
	if got := errcode.CodeOf(err); got != errcode.SRVIO001 {
		t.Fatalf("code = %q (err %v), want %q", got, err, errcode.SRVIO001)
	}
}

func migrateWith(t *testing.T, dir string, files fstest.MapFS) error {
	t.Helper()
	s, err := Open(context.Background(), dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	return migrate(context.Background(), s.db, files, discard)
}

func TestMigrationGuards(t *testing.T) {
	base := fstest.MapFS{"0001_settings.sql": {Data: mustRead(t, "migrations/0001_settings.sql")}}

	tests := []struct {
		name  string
		files fstest.MapFS
		want  errcode.Code
	}{
		{"database newer than binary", fstest.MapFS{}, errcode.SRVMig002},
		{"applied migration edited", fstest.MapFS{"0001_settings.sql": {Data: []byte("-- edited\n")}}, errcode.SRVMig003},
		{"gap in numbering", fstest.MapFS{"0001_settings.sql": base["0001_settings.sql"], "0003_x.sql": {Data: []byte("SELECT 1;")}}, errcode.SRVMig001},
		{"bad file name", fstest.MapFS{"init.sql": {Data: []byte("SELECT 1;")}}, errcode.SRVMig001},
		{"failing statement", fstest.MapFS{"0001_settings.sql": base["0001_settings.sql"], "0002_bad.sql": {Data: []byte("CREATE TABLE t (")}}, errcode.SRVMig001},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := migrateWith(t, t.TempDir(), tt.files)
			if got := errcode.CodeOf(err); got != tt.want {
				t.Fatalf("code = %q (err %v), want %q", got, err, tt.want)
			}
		})
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	dir := t.TempDir()
	files := fstest.MapFS{
		"0001_settings.sql": {Data: mustRead(t, "migrations/0001_settings.sql")},
		"0002_bad.sql":      {Data: []byte("CREATE TABLE half (id INTEGER); CREATE TABLE half (id INTEGER);")},
	}
	if err := migrateWith(t, dir, files); err == nil {
		t.Fatal("expected failure")
	}

	s, err := Open(context.Background(), dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'half'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("half-applied table survived (n=%d, err %v)", n, err)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := migrationFiles.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenTightensOpenDataDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // deliberately too open, to be tightened
		t.Fatal(err)
	}
	s, err := Open(context.Background(), dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %o, want 700", perm)
	}
}
