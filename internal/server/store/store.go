// SPDX-License-Identifier: AGPL-3.0-only

// Package store is the only place nuxd touches SQLite. Schema changes are
// numbered, forward-only migrations in the migrations directory.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registers "sqlite"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Store wraps the nuxd state database.
type Store struct {
	db *sql.DB
	// Now supplies timestamps; nil means time.Now. Tests set it.
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// inTx runs fn in a transaction that takes the write lock immediately (see dsn),
// so a read-then-write inside fn cannot race with another writer.
func (s *Store) inTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// DB exposes the connection pool to modules that own their tables, such as store/secrets.
// Write through InTx so the change shares a transaction with its audit entry.
func (s *Store) DB() *sql.DB { return s.db }

// InTx runs fn in a write transaction that is rolled back if fn fails.
func (s *Store) InTx(ctx context.Context, fn func(tx *sql.Tx) error) error { return s.inTx(ctx, fn) }

// Open creates the data directory if needed, opens nux.db in WAL mode and
// applies pending migrations.
func Open(ctx context.Context, dataDir string, log *slog.Logger) (*Store, error) {
	if err := prepareDataDir(dataDir); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn(filepath.Join(dataDir, "nux.db")))
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVIO001, "open database", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errcode.Wrap(errcode.SRVIO001, "open database", err)
	}

	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		_ = db.Close()
		return nil, errcode.Wrap(errcode.SRVMig001, "load embedded migrations", err)
	}
	if err := migrate(ctx, db, migrations, log); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// prepareDataDir creates the directory and keeps it private to nuxd's user.
func prepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errcode.Wrap(errcode.SRVIO001, "create data directory", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return errcode.Wrap(errcode.SRVIO001, "inspect data directory", err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs the execute bit
		return errcode.New(errcode.SRVIO001, "data directory %s has mode %04o and cannot be restricted to 0700 (%v); make it owned by the user running nuxd", dir, info.Mode().Perm(), err)
	}
	return nil
}

func dsn(path string) string {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "foreign_keys(1)", "busy_timeout(5000)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	return (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
}

// Ping reports whether the database answers.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// SchemaVersion returns the highest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// Close releases the database.
func (s *Store) Close() error {
	return s.db.Close()
}
