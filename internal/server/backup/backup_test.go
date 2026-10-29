// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/backup"
)

var (
	discard  = slog.New(slog.NewTextHandler(io.Discard, nil))
	noEnv    = func(string) string { return "" }
	testPass = []byte("correct horse battery staple")
	fixedNow = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
)

// newDataDir builds a data directory the way nuxd leaves it after first start: a migrated
// database holding one encrypted secret, a master key, a TSDB file and an agent CA key.
func newDataDir(t *testing.T) (dir string, key []byte, secretID string) {
	t.Helper()
	ctx := context.Background()
	dir = filepath.Join(t.TempDir(), "data")
	s, err := store.Open(ctx, dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err = secrets.LoadMasterKey(dir, "", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	secretID, err = box.Put(ctx, s.DB(), []byte("smtp-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "tsdb", "full", "chunk-0001"), "metric-chunk")
	writeFile(t, filepath.Join(dir, "pki", "ca.key"), "agent-ca-key")
	return dir, key, secretID
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func latestSchema(t *testing.T) int {
	t.Helper()
	v, err := store.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantCode(t *testing.T, err error, want errcode.Code) {
	t.Helper()
	if got := errcode.CodeOf(err); got != want {
		t.Fatalf("got code %q (%v), want %s", got, err, want)
	}
}

func archiveOptions(dir string, key []byte, pass []byte) CreateOptions {
	return CreateOptions{DataDir: dir, Passphrase: pass, MasterKey: key, NuxdVersion: "test", Now: fixedNow}
}

func TestBackupRestoreRoundTripYieldsWorkingStoreAndSecrets(t *testing.T) {
	ctx := context.Background()
	dir, key, id := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "state.nuxbak")

	sum, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass))
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Encrypted || !sum.MasterKeyIncluded || sum.KeysExcluded || sum.SchemaVersion != latestSchema(t) {
		t.Fatalf("summary = %+v", sum)
	}
	if _, err := os.Stat(archive + ".partial"); !os.IsNotExist(err) {
		t.Fatal("partial archive left behind")
	}

	target := filepath.Join(t.TempDir(), "restored")
	res, err := Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	if err != nil {
		t.Fatal(err)
	}
	if res.PreviousDir != "" && res.PreviousDir != target+".pre-restore" {
		t.Fatalf("previous dir = %q", res.PreviousDir)
	}

	restoredKey, err := secrets.ReadMasterKey(target, "", noEnv)
	if err != nil || string(restoredKey) != string(key) {
		t.Fatalf("restored master key differs (err %v)", err)
	}
	s, err := store.Open(ctx, target, discard)
	if err != nil {
		t.Fatalf("store.Open on restored data: %v", err)
	}
	defer func() { _ = s.Close() }()
	box, err := secrets.New(restoredKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Get(ctx, s.DB(), id)
	if err != nil || string(got) != "smtp-password" {
		t.Fatalf("secret after restore = %q (err %v)", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "tsdb", "full", "chunk-0001")); err != nil || string(b) != "metric-chunk" { //nolint:gosec // test fixture path
		t.Fatalf("tsdb file after restore = %q (err %v)", b, err)
	}
	info, err := os.Stat(filepath.Join(target, "master.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("master.key mode after restore: %v (err %v)", info.Mode().Perm(), err)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o700 {
		t.Fatalf("restored data dir mode = %o, want 700", info.Mode().Perm())
	}
}

func TestWrongPassphraseLeavesNothingBehind(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	if _, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	_, err := Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: []byte("wrong"), MaxSchemaVersion: latestSchema(t)})
	wantCode(t, err, errcode.BAKAuth001)
	assertNoEntries(t, filepath.Dir(target))
}

func TestTruncatedArchiveRestoreRefused(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	if _, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, data[:len(data)/2], 0o600); err != nil { //nolint:gosec // test fixture path
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	_, err = Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	wantCode(t, err, errcode.BAKTrunc001)
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("target created for a truncated archive")
	}
}

func TestTamperedArchiveRestoreRefused(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	if _, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0x40
	if err := os.WriteFile(archive, data, 0o600); err != nil { //nolint:gosec // test fixture path
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	_, err = Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	wantCode(t, err, errcode.BAKAuth001)
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("target created for a tampered archive")
	}
}

func TestNewerSchemaRefusedBeforeTouchingTarget(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	if _, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "existing")
	writeFile(t, filepath.Join(target, "keep.txt"), "live state")
	_, err := Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t) - 1})
	wantCode(t, err, errcode.BAKVer001)
	if b, err := os.ReadFile(filepath.Join(target, "keep.txt")); err != nil || string(b) != "live state" { //nolint:gosec // test fixture path //nolint:gosec // test fixture path
		t.Fatalf("existing data changed after a refused restore (err %v)", err)
	}
}

func TestRestoreKeepsPreviousDataDirectory(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	if _, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "live")
	writeFile(t, filepath.Join(target, "old.txt"), "previous state")

	res, err := Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(res.PreviousDir, "old.txt")); err != nil || string(b) != "previous state" {
		t.Fatalf("previous state not kept at %s (err %v)", res.PreviousDir, err)
	}
	if _, err := os.Stat(filepath.Join(target, "old.txt")); !os.IsNotExist(err) {
		t.Fatal("old state still in the live directory")
	}

	// A second restore must not overwrite the first .pre-restore.
	_, err = Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	wantCode(t, err, errcode.BAKRest001)
}

func TestRunningNuxdBlocksBackupAndRestore(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	lock, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	_, err = CreateFile(ctx, archive, archiveOptions(dir, key, testPass))
	wantCode(t, err, errcode.BAKLock001)

	// Restore refuses while the lock is held, before any file is written.
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatalf("backup after release: %v", err)
	}
	relock, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relock.Release() }()
	_, err = Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: dir, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	wantCode(t, err, errcode.BAKLock001)
}

func TestUnencryptedArchiveExcludesKeysByDefault(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "plain.nuxbak")
	sum, err := CreateFile(ctx, archive, archiveOptions(dir, key, nil))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Encrypted || sum.MasterKeyIncluded || !sum.KeysExcluded {
		t.Fatalf("summary = %+v; keys must be excluded from an unencrypted archive by default", sum)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, MaxSchemaVersion: latestSchema(t)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"master.key", "pki"} {
		if _, err := os.Stat(filepath.Join(target, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was restored from an unencrypted archive without the flag", name)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "tsdb", "full", "chunk-0001")); err != nil {
		t.Fatalf("ordinary state missing from unencrypted archive: %v", err)
	}
}

func TestUnencryptedArchiveWithKeysFlagIncludesKeys(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	archive := filepath.Join(t.TempDir(), "plain.nuxbak")
	opts := archiveOptions(dir, key, nil)
	opts.IncludeKeys = true
	sum, err := CreateFile(ctx, archive, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.MasterKeyIncluded || sum.KeysExcluded {
		t.Fatalf("summary = %+v", sum)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, RestoreOptions{ArchivePath: archive, DataDir: target, MaxSchemaVersion: latestSchema(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "pki", "ca.key")); err != nil {
		t.Fatalf("agent CA key missing: %v", err)
	}
}

func TestSymlinkInDataDirRefusedAndNoArchiveLeft(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "tsdb", "link")); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "state.nuxbak")
	_, err := CreateFile(ctx, archive, archiveOptions(dir, key, testPass))
	wantCode(t, err, errcode.BAKSrc001)
	assertNoEntries(t, filepath.Dir(archive))
}

func TestArchiveInsideDataDirRefused(t *testing.T) {
	dir, key, _ := newDataDir(t)
	_, err := CreateFile(context.Background(), filepath.Join(dir, "state.nuxbak"), archiveOptions(dir, key, testPass))
	wantCode(t, err, errcode.BAKSrc001)
}

func TestBackupWithoutDatabaseRefused(t *testing.T) {
	_, err := CreateFile(context.Background(), filepath.Join(t.TempDir(), "x.nuxbak"), archiveOptions(t.TempDir(), nil, nil))
	wantCode(t, err, errcode.BAKSrc001)
}

func TestPreUpgradeHookBacksUpBeforeMigrating(t *testing.T) {
	ctx := context.Background()
	dir, key, id := newDataDir(t)
	rollBackToSchema(t, dir, latestSchema(t)-1)

	hook := PreUpgradeHook(PreUpgradeConfig{DataDir: dir, Keep: 3, Getenv: noEnv, NuxdVersion: "test", Log: discard})
	s, err := store.OpenWith(ctx, dir, discard, hook)
	if err != nil {
		t.Fatalf("upgrade with hook: %v", err)
	}
	if v, _ := s.SchemaVersion(ctx); v != latestSchema(t) {
		t.Fatalf("schema after upgrade = %d, want %d", v, latestSchema(t))
	}
	_ = s.Close()

	archives := preUpgradeArchives(t, dir)
	if len(archives) != 1 || !strings.Contains(archives[0], "-v0014-to-v0015") {
		t.Fatalf("pre-upgrade archives = %v, want one v14 to v15 archive", archives)
	}
	_, err = backup.Open(openFile(t, archives[0]), nil)
	wantCode(t, err, errcode.BAKPass001)
	r, err := backup.Open(openFile(t, archives[0]), key)
	if err != nil {
		t.Fatalf("pre-upgrade archive unreadable with the master key: %v", err)
	}
	if !r.Manifest.Encrypted || r.Manifest.SchemaVersion != latestSchema(t)-1 || !r.Manifest.MasterKeyIncluded {
		t.Fatalf("pre-upgrade manifest = %+v", r.Manifest)
	}
	raw, err := os.ReadFile(archives[0]) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "agent-ca-key") || strings.Contains(string(raw), "smtp-password") {
		t.Fatal("pre-upgrade archive holds plaintext keys or secrets")
	}
	if got := openSecretAfter(t, dir, key, id); got != "smtp-password" {
		t.Fatalf("secret after upgrade = %q", got)
	}
}

func TestPreUpgradeHookKeepsNewestArchives(t *testing.T) {
	dir, _, _ := newDataDir(t)
	backupDir := filepath.Join(dir, "backups")
	for _, name := range []string{"a", "b", "c", "d"} {
		writeFile(t, filepath.Join(backupDir, "pre-upgrade-2026-0"+name+"-v0001-to-v0002.nuxbak"), name)
	}
	writeFile(t, filepath.Join(backupDir, "unrelated.txt"), "keep me")
	if err := prune(backupDir, 2); err != nil {
		t.Fatal(err)
	}
	got := preUpgradeArchives(t, dir)
	if len(got) != 2 || !strings.HasSuffix(got[0], "2026-0c-v0001-to-v0002.nuxbak") || !strings.HasSuffix(got[1], "2026-0d-v0001-to-v0002.nuxbak") {
		t.Fatalf("kept %v, want the two newest", got)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "unrelated.txt")); err != nil {
		t.Fatal("prune removed a file it does not own")
	}
}

func TestPreUpgradeFailureStopsMigration(t *testing.T) {
	ctx := context.Background()
	dir, _, _ := newDataDir(t)
	rollBackToSchema(t, dir, latestSchema(t)-1)
	// A regular file where the backups directory must go makes the pre-upgrade backup impossible.
	writeFile(t, filepath.Join(dir, "backups"), "not a directory")

	hook := PreUpgradeHook(PreUpgradeConfig{DataDir: dir, Keep: 3, Getenv: noEnv})
	_, err := store.OpenWith(ctx, dir, discard, hook)
	wantCode(t, err, errcode.BAKUpg001)

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "nux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v int
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != latestSchema(t)-1 {
		t.Fatalf("schema advanced to %d despite the failed backup", v)
	}
}

func TestPreUpgradeDisabledWithZeroKeep(t *testing.T) {
	if PreUpgradeHook(PreUpgradeConfig{DataDir: t.TempDir(), Keep: 0}) != nil {
		t.Fatal("hook should be nil when keep is 0")
	}
}

// rollBackToSchema makes the database look one or more migrations behind, so the next start
// has pending migrations to apply. The migrations' indexes are dropped so they can be recreated.
func rollBackToSchema(t *testing.T, dir string, version int) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "nux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, idx := range []string{"audit_log_actor", "audit_log_action", "audit_log_target", "audit_log_ts"} {
		if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS `+idx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version > ?`, version); err != nil {
		t.Fatal(err)
	}
}

func preUpgradeArchives(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "backups", "pre-upgrade-*.nuxbak"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func openFile(t *testing.T, path string) io.Reader {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func assertNoEntries(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".partial") || strings.Contains(e.Name(), ".restore-") || e.Name() == "state.nuxbak" {
			t.Fatalf("leftover %s in %s", e.Name(), dir)
		}
	}
}

func openSecretAfter(t *testing.T, dir string, key []byte, id string) string {
	t.Helper()
	s, err := store.Open(context.Background(), dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Get(context.Background(), s.DB(), id)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestPreUpgradeHookFailsClosedWithoutMasterKey(t *testing.T) {
	ctx := context.Background()
	dir, _, _ := newDataDir(t)
	rollBackToSchema(t, dir, latestSchema(t)-1)
	if err := os.Remove(filepath.Join(dir, "master.key")); err != nil {
		t.Fatal(err)
	}

	hook := PreUpgradeHook(PreUpgradeConfig{DataDir: dir, Keep: 3, Getenv: noEnv})
	_, err := store.OpenWith(ctx, dir, discard, hook)
	wantCode(t, err, errcode.BAKUpg001)
	if got := preUpgradeArchives(t, dir); len(got) != 0 {
		t.Fatalf("an unencrypted pre-upgrade archive was written: %v", got)
	}
}

func TestRestoreVerifiesAuditChain(t *testing.T) {
	ctx := context.Background()
	dir, key, _ := newDataDir(t)
	seedAudit(t, dir, 3)

	clean := filepath.Join(t.TempDir(), "clean.nuxbak")
	if _, err := CreateFile(ctx, clean, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, RestoreOptions{ArchivePath: clean, DataDir: filepath.Join(t.TempDir(), "ok"), Passphrase: testPass, MaxSchemaVersion: latestSchema(t)}); err != nil {
		t.Fatalf("intact audit chain refused: %v", err)
	}

	tamperAudit(t, dir)
	broken := filepath.Join(t.TempDir(), "broken.nuxbak")
	if _, err := CreateFile(ctx, broken, archiveOptions(dir, key, testPass)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "live")
	writeFile(t, filepath.Join(target, "keep.txt"), "live state")
	_, err := Restore(ctx, RestoreOptions{ArchivePath: broken, DataDir: target, Passphrase: testPass, MaxSchemaVersion: latestSchema(t)})
	wantCode(t, err, errcode.BAKAudit001)
	if b, err := os.ReadFile(filepath.Join(target, "keep.txt")); err != nil || string(b) != "live state" { //nolint:gosec // test fixture path
		t.Fatalf("live directory changed after a refused restore (err %v)", err)
	}
	if _, err := os.Stat(target + ".pre-restore"); !os.IsNotExist(err) {
		t.Fatal("a .pre-restore directory was created for a refused restore")
	}
	assertNoEntries(t, filepath.Dir(target))
}

// seedAudit appends n audit events through the store, so the chain has real hashes.
func seedAudit(t *testing.T, dir string, n int) {
	t.Helper()
	s, err := store.Open(context.Background(), dir, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for i := 1; i <= n; i++ {
		err := s.RecordAudit(context.Background(), audit.Event{
			ActorType: "user", ActorID: "01SEED", Action: "seed.thing", TargetType: "seed", TargetID: strconv.Itoa(i),
			IP: "203.0.113.9", Result: audit.ResultSuccess,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// tamperAudit edits an audit row directly in the database, as someone with file access could.
// The append-only trigger is dropped first, which is the attack the chain is meant to expose.
func tamperAudit(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "nux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_log SET action = 'forged.action' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
}
