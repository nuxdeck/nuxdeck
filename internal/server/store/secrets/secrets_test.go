// SPDX-License-Identifier: AGPL-3.0-only

package secrets_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

type fixture struct {
	dir string
	db  *store.Store
	box *secrets.Box
	key []byte
}

func newBox(t *testing.T, key []byte) *secrets.Box {
	t.Helper()
	b, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	return &fixture{dir: dir, db: db, box: newBox(t, key), key: key}
}

func (f *fixture) put(t *testing.T, pt string) string {
	t.Helper()
	id, err := f.box.Put(context.Background(), f.db.DB(), []byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) get(id string) (string, error) {
	b, err := f.box.Get(context.Background(), f.db.DB(), id)
	return string(b), err
}

func TestRoundTripReplaceDelete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.put(t, "hunter2")
	if got, err := f.get(id); err != nil || got != "hunter2" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if err := f.box.Replace(ctx, f.db.DB(), id, []byte("hunter3")); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.get(id); got != "hunter3" {
		t.Fatalf("after Replace = %q", got)
	}
	if err := f.box.Delete(ctx, f.db.DB(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.get(id); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := f.box.Delete(ctx, f.db.DB(), id); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("second Delete = %v", err)
	}
	if err := f.box.Replace(ctx, f.db.DB(), "nope", []byte("x")); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Replace unknown = %v", err)
	}
}

func TestEmptyAndLargePlaintext(t *testing.T) {
	f := newFixture(t)
	big := bytes.Repeat([]byte{0xAB}, 1<<20)
	for name, pt := range map[string][]byte{"empty": {}, "large": big} {
		id, err := f.box.Put(context.Background(), f.db.DB(), pt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := f.box.Get(context.Background(), f.db.DB(), id)
		if err != nil || !bytes.Equal(got, pt) {
			t.Errorf("%s: round trip failed (%v)", name, err)
		}
	}
}

func TestNoncesAndKeysAreUnique(t *testing.T) {
	f := newFixture(t)
	seenNonce, seenWrap := map[string]bool{}, map[string]bool{}
	for range 50 {
		id := f.put(t, "same plaintext")
		var nonce, wrapped []byte
		if err := f.db.DB().QueryRow(`SELECT nonce, wrapped_dek FROM secrets WHERE id = ?`, id).Scan(&nonce, &wrapped); err != nil {
			t.Fatal(err)
		}
		if seenNonce[string(nonce)] || seenWrap[string(wrapped)] {
			t.Fatal("nonce or wrapped key repeated")
		}
		seenNonce[string(nonce)], seenWrap[string(wrapped)] = true, true
		if wrapped[0] != 1 {
			t.Fatalf("wrapped_dek version byte = %d, want 1", wrapped[0])
		}
	}
}

func TestTamperDetection(t *testing.T) {
	for _, col := range []string{"ciphertext", "nonce", "wrapped_dek"} {
		f := newFixture(t)
		id := f.put(t, "top secret")
		var orig []byte
		if err := f.db.DB().QueryRow(`SELECT `+col+` FROM secrets WHERE id = ?`, id).Scan(&orig); err != nil {
			t.Fatal(err)
		}
		for i := range orig {
			for bit := 0; bit < 8; bit += 7 { // lowest and highest bit of every byte
				mut := bytes.Clone(orig)
				mut[i] ^= 1 << bit
				if _, err := f.db.DB().Exec(`UPDATE secrets SET `+col+` = ? WHERE id = ?`, mut, id); err != nil {
					t.Fatal(err)
				}
				if _, err := f.get(id); errcode.CodeOf(err) != errcode.SRVSec002 {
					t.Fatalf("%s byte %d bit %d: err = %v, want SRV-SEC-002", col, i, bit, err)
				}
			}
		}
		// Truncation and extension are tampering too.
		for _, mut := range [][]byte{orig[:len(orig)-1], append(bytes.Clone(orig), 0), {}} {
			if _, err := f.db.DB().Exec(`UPDATE secrets SET `+col+` = ? WHERE id = ?`, mut, id); err != nil {
				t.Fatal(err)
			}
			if _, err := f.get(id); errcode.CodeOf(err) != errcode.SRVSec002 {
				t.Fatalf("%s resized to %d: err = %v", col, len(mut), err)
			}
		}
		if _, err := f.db.DB().Exec(`UPDATE secrets SET `+col+` = ? WHERE id = ?`, orig, id); err != nil {
			t.Fatal(err)
		}
		if got, err := f.get(id); err != nil || got != "top secret" {
			t.Fatalf("%s restored: %q, %v", col, got, err)
		}
	}
}

func TestWrongMasterKey(t *testing.T) {
	f := newFixture(t)
	id := f.put(t, "abc")
	other := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(other)
	_, err := newBox(t, other).Get(context.Background(), f.db.DB(), id)
	if errcode.CodeOf(err) != errcode.SRVSec002 {
		t.Fatalf("err = %v, want SRV-SEC-002", err)
	}
}

func TestNewRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := secrets.New(make([]byte, n)); errcode.CodeOf(err) != errcode.SRVSec001 {
			t.Errorf("New(%d bytes) = %v", n, err)
		}
	}
}

func TestSwappedRowsRejected(t *testing.T) {
	f := newFixture(t)
	a, b := f.put(t, "secret A"), f.put(t, "secret B")
	// Move all of A's sealed material onto B's id.
	if _, err := f.db.DB().Exec(`UPDATE secrets SET ciphertext = (SELECT ciphertext FROM secrets WHERE id = ?),
		nonce = (SELECT nonce FROM secrets WHERE id = ?), wrapped_dek = (SELECT wrapped_dek FROM secrets WHERE id = ?) WHERE id = ?`, a, a, a, b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.get(b); errcode.CodeOf(err) != errcode.SRVSec002 {
		t.Fatalf("copied row opened: %v", err)
	}
	if got, _ := f.get(a); got != "secret A" {
		t.Fatalf("original damaged: %q", got)
	}

	// Swapping only the data (keeping each row's own wrapped key) fails too.
	c := f.put(t, "secret C")
	if _, err := f.db.DB().Exec(`UPDATE secrets SET ciphertext = (SELECT ciphertext FROM secrets WHERE id = ?), nonce = (SELECT nonce FROM secrets WHERE id = ?) WHERE id = ?`, a, a, c); err != nil {
		t.Fatal(err)
	}
	if _, err := f.get(c); errcode.CodeOf(err) != errcode.SRVSec002 {
		t.Fatalf("swapped ciphertext opened: %v", err)
	}
}

func TestPlaintextNeverOnDisk(t *testing.T) {
	const marker = "PLAINTEXT-MARKER-7f3a9c1e-do-not-store-0123456789"
	dir := t.TempDir()
	ctx := context.Background()
	db, err := store.Open(ctx, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	box := newBox(t, key)

	// Control, in a separate database: the scan must see a marker that is stored unencrypted.
	ctlDir := t.TempDir()
	ctl, err := store.Open(ctx, ctlDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.DB().Exec(`CREATE TABLE control (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.DB().Exec(`INSERT INTO control VALUES (?)`, marker); err != nil {
		t.Fatal(err)
	}
	if !diskContains(t, ctlDir, marker) {
		t.Fatal("control marker not found on disk; the scan is blind")
	}
	_ = ctl.Close()

	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		_, err := box.Put(ctx, tx, []byte(marker))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if wal, err := os.Stat(filepath.Join(dir, "nux.db-wal")); err != nil || wal.Size() == 0 {
		t.Fatalf("expected a non-empty WAL after Put (err %v)", err)
	}
	if diskContains(t, dir, marker) {
		t.Fatal("plaintext found in the database or WAL after Put")
	}
	if _, err := db.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if diskContains(t, dir, marker) {
		t.Fatal("plaintext found on disk after checkpoint and close")
	}
}

// diskContains scans every file in dir (database, WAL, shared memory) for needle.
func diskContains(t *testing.T, dir, needle string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(needle)) {
			return true
		}
	}
	return false
}

func TestRollbackLeavesNoSecret(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var id string
	boom := errors.New("owner row failed")
	err := f.db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		if id, err = f.box.Put(ctx, tx, []byte("pending")); err != nil {
			return err
		}
		if got, err := f.box.Get(ctx, tx, id); err != nil || string(got) != "pending" {
			t.Errorf("secret not visible inside its own transaction: %q %v", got, err)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.get(id); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("secret survived rollback: %v", err)
	}
	if has, err := secrets.Any(ctx, f.db.DB()); err != nil || has {
		t.Fatalf("Any = %v, %v after rollback", has, err)
	}
}

func TestConcurrentPutGet(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				want := bytes.Repeat([]byte{byte(w & 0xff)}, 8+i)
				id, err := f.box.Put(ctx, f.db.DB(), want)
				if err != nil {
					errs <- err
					return
				}
				got, err := f.box.Get(ctx, f.db.DB(), id)
				if err != nil || !bytes.Equal(got, want) {
					errs <- errors.Join(errors.New("mismatch"), err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
