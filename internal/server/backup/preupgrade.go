// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

const preUpgradePrefix = "pre-upgrade-"

// PreUpgradeConfig configures the automatic backup taken before migrations.
type PreUpgradeConfig struct {
	DataDir     string
	Keep        int
	KeyFile     string
	Getenv      func(string) string
	NuxdVersion string
	Log         *slog.Logger
}

// PreUpgradeHook returns the store hook that writes a backup before pending migrations
// run. It returns nil when Keep is 0, which turns the feature off.
//
// The archive is always encrypted. Its passphrase is the master key itself, so it needs no
// new secret, and it includes master.key and the agent CA key. Restore it with
// --master-key-file. Its strength is that of the master key, which sits in the same data
// directory: anyone who can read both the archive and the key can open it. The archive keeps
// the same protection as the data directory and is not a separate trust boundary. An upgrade
// that cannot be backed up, including one with no master key to encrypt with, stops with
// BAK-UPG-001 and does not run.
func PreUpgradeHook(cfg PreUpgradeConfig) store.BeforeUpgrade {
	if cfg.Keep <= 0 {
		return nil
	}
	return func(ctx context.Context, db *sql.DB, from, to int) error {
		dir := filepath.Join(cfg.DataDir, backupsDir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errcode.Wrap(errcode.BAKUpg001, "create backups directory", err)
		}
		key, err := secrets.ReadMasterKey(cfg.DataDir, cfg.KeyFile, cfg.Getenv)
		if err != nil {
			return errcode.Wrap(errcode.BAKUpg001, "read master key", err)
		}
		if key == nil {
			return errcode.New(errcode.BAKUpg001, "no master key is available to encrypt the pre-upgrade backup")
		}
		now := time.Now().UTC()
		name := fmt.Sprintf("%s%s-v%04d-to-v%04d%s", preUpgradePrefix, now.Format("20060102T150405.000000000Z"), from, to, archiveExt)
		path := filepath.Join(dir, name)
		err = writeFileAtomically(path, func(w io.Writer) error {
			work, err := os.MkdirTemp(dir, ".work-")
			if err != nil {
				return errcode.Wrap(errcode.BAKUpg001, "create scratch directory", err)
			}
			defer func() { _ = os.RemoveAll(work) }()
			_, err = writeTo(ctx, db, w, CreateOptions{DataDir: cfg.DataDir, Passphrase: key, MasterKey: key, NuxdVersion: cfg.NuxdVersion, Now: now})
			return err
		})
		if err != nil {
			return errcode.Wrap(errcode.BAKUpg001, "write pre-upgrade backup", err)
		}
		if cfg.Log != nil {
			cfg.Log.Info("wrote pre-upgrade backup", "path", path, "from_schema", from, "to_schema", to)
		}
		if err := prune(dir, cfg.Keep); err != nil && cfg.Log != nil {
			cfg.Log.Warn("could not delete old pre-upgrade backups", "error", err)
		}
		return nil
	}
}

// prune deletes all but the newest keep pre-upgrade archives. Names start with a fixed-width
// UTC timestamp, so lexical order is age order.
func prune(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, preUpgradePrefix) && strings.HasSuffix(n, archiveExt) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for i := 0; i < len(names)-keep; i++ {
		if err := os.Remove(filepath.Join(dir, names[i])); err != nil {
			return err
		}
	}
	return nil
}
