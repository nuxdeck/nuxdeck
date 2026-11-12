// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/pkg/backup"
)

// RestoreOptions describes a restore into DataDir.
type RestoreOptions struct {
	ArchivePath string
	DataDir     string
	Passphrase  []byte
	// MaxSchemaVersion is the newest schema this nuxd understands.
	MaxSchemaVersion int
}

// RestoreResult reports the restored state and where the previous data directory went.
type RestoreResult struct {
	Manifest    backup.Manifest
	PreviousDir string
	Files       int
}

// Restore replaces DataDir with the archive's contents. Nothing in DataDir changes until the
// whole archive is extracted, every checksum matches, and the database passes an integrity
// check. The old directory is renamed to DataDir + ".pre-restore" and kept, never deleted.
func Restore(ctx context.Context, opts RestoreOptions) (RestoreResult, error) {
	if !filepath.IsAbs(opts.DataDir) {
		return RestoreResult{}, errcode.New(errcode.BAKRest001, "the data directory must be an absolute path, got %q", opts.DataDir)
	}
	in, err := os.Open(opts.ArchivePath) //nolint:gosec // operator-supplied archive path
	if err != nil {
		return RestoreResult{}, errcode.Wrap(errcode.BAKFmt001, "open archive", err)
	}
	defer func() { _ = in.Close() }()

	reader, err := backup.Open(in, opts.Passphrase)
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() { _ = reader.Close() }()

	preDir := opts.DataDir + ".pre-restore"
	if _, err := os.Lstat(preDir); err == nil {
		return RestoreResult{}, errcode.New(errcode.BAKRest001, "%s already exists; move it aside so the previous state is not lost", preDir)
	}
	if err := os.MkdirAll(filepath.Dir(opts.DataDir), 0o750); err != nil {
		return RestoreResult{}, errcode.Wrap(errcode.BAKRest001, "create parent of data directory", err)
	}
	if _, err := os.Lstat(opts.DataDir); err == nil {
		lock, err := LockDataDir(opts.DataDir)
		if err != nil {
			return RestoreResult{}, err
		}
		defer func() { _ = lock.Release() }()
	}

	staging, err := os.MkdirTemp(filepath.Dir(opts.DataDir), "."+filepath.Base(opts.DataDir)+".restore-")
	if err != nil {
		return RestoreResult{}, errcode.Wrap(errcode.BAKRest001, "create staging directory", err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(staging)
		}
	}()

	m, err := reader.Extract(staging, backup.ExtractOptions{MaxSchemaVersion: opts.MaxSchemaVersion})
	if err != nil {
		return RestoreResult{}, err
	}
	if err := verifyDatabase(ctx, filepath.Join(staging, dbFile), m.SchemaVersion); err != nil {
		return RestoreResult{}, err
	}
	if err := verifyAuditChain(ctx, staging); err != nil {
		return RestoreResult{}, err
	}

	res := RestoreResult{Manifest: m, PreviousDir: preDir}
	if _, err := os.Lstat(opts.DataDir); err == nil {
		if err := os.Rename(opts.DataDir, preDir); err != nil {
			return RestoreResult{}, errcode.Wrap(errcode.BAKRest001, "move the data directory aside", err)
		}
		if err := os.Rename(staging, opts.DataDir); err != nil {
			if rbErr := os.Rename(preDir, opts.DataDir); rbErr != nil {
				return RestoreResult{}, errcode.New(errcode.BAKRest001, "restore failed (%v) and the previous state could not be put back; it is in %s", err, preDir)
			}
			return RestoreResult{}, errcode.Wrap(errcode.BAKRest001, "put the restored data directory in place", err)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := os.Rename(staging, opts.DataDir); err != nil {
			return RestoreResult{}, errcode.Wrap(errcode.BAKRest001, "put the restored data directory in place", err)
		}
	} else {
		return RestoreResult{}, errcode.Wrap(errcode.BAKRest001, "inspect data directory", err)
	}
	done = true
	return res, nil
}

// verifyDatabase checks the restored database is readable and matches the schema the
// manifest recorded, so a restore never yields a store that cannot open.
func verifyDatabase(ctx context.Context, path string, schema int) error {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "open restored database", err)
	}
	defer func() { _ = db.Close() }()

	var check string
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		return errcode.New(errcode.BAKFmt001, "restored database failed its integrity check: %s (%v)", check, err)
	}
	var got sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&got); err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "read restored schema version", err)
	}
	if int(got.Int64) != schema {
		return errcode.New(errcode.BAKFmt001, "restored database is at schema %d but the archive recorded %d", got.Int64, schema)
	}
	return nil
}

// verifyAuditChain walks the restored audit hash chain (AUD-2) before the swap. Opening the
// store may apply migrations that are pending for an older archive, which is the same upgrade
// nuxd would run on its next start, and it happens in staging, so the live directory is safe.
func verifyAuditChain(ctx context.Context, staging string) error {
	s, err := store.OpenWith(ctx, staging, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	v, err := s.VerifyAudit(ctx)
	if err != nil {
		return errcode.Wrap(errcode.BAKRest001, "read restored audit log", err)
	}
	if !v.OK {
		return errcode.New(errcode.BAKAudit001, "entry %d does not verify: %s", v.BrokenAt, v.Reason)
	}
	return nil
}
