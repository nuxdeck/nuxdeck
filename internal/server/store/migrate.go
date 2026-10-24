// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

type migration struct {
	version  int
	name     string
	checksum string
	sql      string
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVMig001, "list migrations", err)
	}

	var out []migration
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, errcode.New(errcode.SRVMig001, "migration file %q must be named NNNN_description.sql", e.Name())
		}
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, errcode.Wrap(errcode.SRVMig001, "read "+e.Name(), err)
		}
		v, _ := strconv.Atoi(m[1])
		sum := sha256.Sum256(body)
		out = append(out, migration{version: v, name: e.Name(), checksum: hex.EncodeToString(sum[:]), sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, errcode.New(errcode.SRVMig001, "migration numbers must start at 0001 with no gaps; found %s at position %d", m.name, i+1)
		}
	}
	return out, nil
}

func migrate(ctx context.Context, db *sql.DB, fsys fs.FS, log *slog.Logger) error {
	migrations, err := loadMigrations(fsys)
	if err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		checksum   TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return errcode.Wrap(errcode.SRVMig001, "create schema_migrations", err)
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return err
	}
	for v, sum := range applied {
		if v > len(migrations) {
			return errcode.New(errcode.SRVMig002, "database has migration %04d but this build knows only %d", v, len(migrations))
		}
		if migrations[v-1].checksum != sum {
			return errcode.New(errcode.SRVMig003, "migration %s changed after it was applied", migrations[v-1].name)
		}
	}

	for _, m := range migrations {
		if _, done := applied[m.version]; done {
			continue
		}
		if err := apply(ctx, db, m); err != nil {
			return err
		}
		log.Info("applied database migration", "version", m.version, "name", m.name)
	}
	return nil
}

func appliedMigrations(ctx context.Context, db *sql.DB) (map[int]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVMig001, "read schema_migrations", err)
	}
	defer func() { _ = rows.Close() }()

	applied := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, errcode.Wrap(errcode.SRVMig001, "scan schema_migrations", err)
		}
		applied[v] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, errcode.Wrap(errcode.SRVMig001, "read schema_migrations", err)
	}
	return applied, nil
}

func apply(ctx context.Context, db *sql.DB, m migration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errcode.Wrap(errcode.SRVMig001, fmt.Sprintf("begin %s", m.name), err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, m.sql); err != nil {
		return errcode.Wrap(errcode.SRVMig001, "apply "+m.name, err)
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.version, m.name, m.checksum, time.Now().UnixMilli()); err != nil {
		return errcode.Wrap(errcode.SRVMig001, "record "+m.name, err)
	}
	if err = tx.Commit(); err != nil {
		return errcode.Wrap(errcode.SRVMig001, "commit "+m.name, err)
	}
	return nil
}
