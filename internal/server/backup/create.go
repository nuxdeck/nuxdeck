// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registers "sqlite"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/backup"
)

const (
	dbFile         = "nux.db"
	backupsDir     = "backups"
	archiveExt     = ".nuxbak"
	setupTokenFile = "setup-token"
	pkiDir         = "pki"
	masterKeyName  = secrets.GeneratedKeyFile
)

// skipTop are top-level entries never copied as files. The database goes in through a
// snapshot, the lock is not state, the setup token is a one-time secret, and backups/ holds
// archives and scratch space.
var skipTop = map[string]bool{
	dbFile: true, dbFile + "-wal": true, dbFile + "-shm": true, dbFile + "-journal": true,
	LockFile: true, setupTokenFile: true, backupsDir: true,
}

// keyTop are the sensitive top-level entries. They are copied only into encrypted archives or
// when the operator explicitly accepts unencrypted keys.
var keyTop = map[string]bool{masterKeyName: true, pkiDir: true}

// CreateOptions describes one archive.
type CreateOptions struct {
	DataDir string
	// Passphrase encrypts the archive. Nil writes an unencrypted archive.
	Passphrase []byte
	// IncludeKeys copies the master key and the agent CA key into an unencrypted archive. An
	// encrypted archive always includes them, because a restore needs them to decrypt secrets.
	IncludeKeys bool
	// MasterKey is the resolved secrets master key. It is written as master.key when keys are included.
	MasterKey   []byte
	NuxdVersion string
	Now         time.Time
}

// Summary reports what an archive holds and what it left out.
type Summary struct {
	Path              string
	SchemaVersion     int
	Encrypted         bool
	MasterKeyIncluded bool
	// KeysExcluded is true when sensitive entries exist but were left out of this archive.
	KeysExcluded bool
	Files        int
	Bytes        int64
}

type entry struct {
	rel  string
	abs  string
	dir  bool
	size int64
}

// CreateFile writes an archive to path. It holds the data-directory lock for the whole
// copy, so nuxd cannot write during it, and it refuses an output inside the data directory.
func CreateFile(ctx context.Context, path string, opts CreateOptions) (Summary, error) {
	if inside(opts.DataDir, path) {
		return Summary{}, errcode.New(errcode.BAKSrc001, "write the archive outside the data directory %s", opts.DataDir)
	}
	lock, err := LockDataDir(opts.DataDir)
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = lock.Release() }()

	db, err := openSnapshotSource(ctx, opts.DataDir)
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = db.Close() }()

	var sum Summary
	err = writeFileAtomically(path, func(w io.Writer) error {
		var werr error
		sum, werr = writeTo(ctx, db, w, opts)
		return werr
	})
	if err != nil {
		return Summary{}, err
	}
	sum.Path = path
	return sum, nil
}

// writeTo writes the archive for a database that the caller has opened and whose data
// directory is locked.
func writeTo(ctx context.Context, db *sql.DB, w io.Writer, opts CreateOptions) (Summary, error) {
	keys := len(opts.Passphrase) > 0 || opts.IncludeKeys
	schema, err := schemaVersion(ctx, db)
	if err != nil {
		return Summary{}, err
	}
	entries, keysExcluded, err := collect(opts.DataDir, keys)
	if err != nil {
		return Summary{}, err
	}

	if err := os.MkdirAll(filepath.Join(opts.DataDir, backupsDir), 0o700); err != nil {
		return Summary{}, errcode.Wrap(errcode.BAKSrc001, "create backups directory", err)
	}
	work, err := os.MkdirTemp(filepath.Join(opts.DataDir, backupsDir), ".work-")
	if err != nil {
		return Summary{}, errcode.Wrap(errcode.BAKSrc001, "create scratch directory", err)
	}
	defer func() { _ = os.RemoveAll(work) }()

	snapshot := filepath.Join(work, dbFile)
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return Summary{}, errcode.Wrap(errcode.BAKSrc001, "snapshot database", err)
	}
	snapInfo, err := os.Stat(snapshot)
	if err != nil {
		return Summary{}, errcode.Wrap(errcode.BAKSrc001, "stat database snapshot", err)
	}

	sum := Summary{SchemaVersion: schema, Encrypted: len(opts.Passphrase) > 0, KeysExcluded: keysExcluded}
	sum.MasterKeyIncluded = keys && len(opts.MasterKey) > 0
	m := backup.Manifest{
		NuxdVersion:       opts.NuxdVersion,
		CreatedAt:         opts.Now,
		SchemaVersion:     schema,
		MasterKeyIncluded: sum.MasterKeyIncluded,
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now()
	}
	aw, err := backup.NewWriter(w, m, opts.Passphrase, backup.DefaultKDF)
	if err != nil {
		return Summary{}, err
	}

	if err := addFileFrom(aw, dbFile, snapInfo.Size(), snapshot); err != nil {
		return Summary{}, err
	}
	sum.Files++
	sum.Bytes += snapInfo.Size()
	for _, e := range entries {
		if e.dir {
			if err := aw.AddDir(e.rel); err != nil {
				return Summary{}, err
			}
			continue
		}
		if err := addFileFrom(aw, e.rel, e.size, e.abs); err != nil {
			return Summary{}, err
		}
		sum.Files++
		sum.Bytes += e.size
	}
	if sum.MasterKeyIncluded {
		encoded := []byte(base64.StdEncoding.EncodeToString(opts.MasterKey) + "\n")
		if err := aw.AddFile(masterKeyName, int64(len(encoded)), bytes.NewReader(encoded)); err != nil {
			return Summary{}, err
		}
		sum.Files++
		sum.Bytes += int64(len(encoded))
	}
	if err := aw.Close(); err != nil {
		return Summary{}, err
	}
	return sum, nil
}

func addFileFrom(aw *backup.Writer, name string, size int64, path string) error {
	f, err := os.Open(path) //nolint:gosec // path comes from the data directory walk or our own scratch directory
	if err != nil {
		return errcode.Wrap(errcode.BAKSrc001, "open "+name, err)
	}
	defer func() { _ = f.Close() }()
	return aw.AddFile(name, size, f)
}

// collect lists the data-directory entries to copy, sorted for a stable archive order.
// Symbolic links and special files are refused: copying a link could leak files outside the
// data directory into the archive.
func collect(dataDir string, keys bool) (entries []entry, keysExcluded bool, err error) {
	walkErr := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errcode.Wrap(errcode.BAKSrc001, "read data directory", err)
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		slashRel := filepath.ToSlash(rel)
		top := strings.SplitN(slashRel, "/", 2)[0]
		topLevel := top == slashRel

		if topLevel && skipTop[top] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if topLevel && top == masterKeyName {
			// The key is written from the resolved value, which may come from the environment
			// or a file elsewhere, so the file in the data directory is never copied as is.
			keysExcluded = keysExcluded || !keys
			return nil
		}
		if topLevel && top == pkiDir && !keys {
			keysExcluded = true
			return filepath.SkipDir
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return errcode.New(errcode.BAKSrc001, "%s is a symbolic link; replace it with its target before backing up", slashRel)
		case d.IsDir():
			entries = append(entries, entry{rel: slashRel, dir: true})
			return nil
		case !d.Type().IsRegular():
			return errcode.New(errcode.BAKSrc001, "%s is not a regular file", slashRel)
		}
		info, err := d.Info()
		if err != nil {
			return errcode.Wrap(errcode.BAKSrc001, "stat "+slashRel, err)
		}
		entries = append(entries, entry{rel: slashRel, abs: path, size: info.Size()})
		return nil
	})
	if walkErr != nil {
		return nil, false, walkErr
	}
	return entries, keysExcluded, nil
}

// openSnapshotSource opens the database for reading. Opening never migrates: the schema is
// whatever the archive must record.
func openSnapshotSource(ctx context.Context, dataDir string) (*sql.DB, error) {
	path := filepath.Join(dataDir, dbFile)
	if _, err := os.Stat(path); err != nil {
		return nil, errcode.Wrap(errcode.BAKSrc001, "no database to back up in "+dataDir, err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVIO001, "open database", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errcode.Wrap(errcode.SRVIO001, "open database", err)
	}
	return db, nil
}

func schemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, errcode.Wrap(errcode.BAKSrc001, "read schema version", err)
	}
	return int(v.Int64), nil
}

// writeFileAtomically writes to path.partial and renames it into place, so a failed or
// interrupted backup never leaves a file that looks complete.
func writeFileAtomically(path string, write func(io.Writer) error) error {
	partial := path + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // path chosen by the operator or the pre-upgrade hook
	if err != nil {
		return errcode.Wrap(errcode.BAKSrc001, "create archive", err)
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(partial)
		return err
	}
	if err := write(f); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(errcode.Wrap(errcode.BAKSrc001, "flush archive", err))
	}
	if err := f.Close(); err != nil {
		return fail(errcode.Wrap(errcode.BAKSrc001, "close archive", err))
	}
	if err := os.Rename(partial, path); err != nil {
		return fail(errcode.Wrap(errcode.BAKSrc001, "publish archive", err))
	}
	return nil
}

func inside(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// ReadPassphraseFile returns the passphrase in a file, without its trailing newline. The file
// is read whole, and its contents are never echoed in errors.
func ReadPassphraseFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied passphrase file
	if err != nil {
		return nil, errcode.Wrap(errcode.BAKPass001, "read passphrase file", err)
	}
	pass := bytes.TrimRight(data, "\r\n")
	if len(pass) == 0 {
		return nil, errcode.New(errcode.BAKPass001, "passphrase file %s is empty", path)
	}
	return pass, nil
}
