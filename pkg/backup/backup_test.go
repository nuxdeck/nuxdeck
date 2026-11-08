// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// testKDF keeps tests fast; the real default is exercised by the server tests.
var testKDF = KDF{Time: 1, MemoryKiB: 64, Threads: 1}

var testPass = []byte("correct horse battery staple")

func testManifest() Manifest {
	return Manifest{NuxdVersion: "test", CreatedAt: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), SchemaVersion: 15}
}

// build writes an archive with two payload files and returns its bytes and the expected
// file contents. Passphrase nil writes an unencrypted archive.
func build(t *testing.T, passphrase []byte) ([]byte, map[string]string) {
	t.Helper()
	files := map[string]string{"nux.db": strings.Repeat("database-", 20000), "tsdb/chunks/0001": "chunk"}
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testManifest(), passphrase, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddDir("tsdb"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nux.db", "tsdb/chunks/0001"} {
		if err := w.AddFile(name, int64(len(files[name])), strings.NewReader(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), files
}

// craft writes raw tar entries through a Writer, bypassing its name checks, so tests can
// produce archives a hostile or buggy producer might write.
func craft(t *testing.T, passphrase []byte, entries ...func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testManifest(), passphrase, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		e(w.tw)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func regEntry(name, body string) func(*tar.Writer) {
	return func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
}

func wantCode(t *testing.T, err error, want errcode.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %s", want)
	}
	if got := errcode.CodeOf(err); got != want {
		t.Fatalf("got code %q (%v), want %s", got, err, want)
	}
}

func extractTo(t *testing.T, archive []byte, passphrase []byte, opts ExtractOptions) (string, error) {
	t.Helper()
	r, err := Open(bytes.NewReader(archive), passphrase)
	if err != nil {
		return "", err
	}
	dst := filepath.Join(t.TempDir(), "staging")
	if _, err := r.Extract(dst, opts); err != nil {
		return dst, err
	}
	return dst, nil
}

func defaultOpts() ExtractOptions { return ExtractOptions{MaxSchemaVersion: 15} }

func TestRoundTripEncryptedAndPlain(t *testing.T) {
	for _, tc := range []struct {
		name string
		pass []byte
	}{{"encrypted", testPass}, {"plain", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			archive, files := build(t, tc.pass)
			dst, err := extractTo(t, archive, tc.pass, defaultOpts())
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range files {
				got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(name))) //nolint:gosec // test fixture path
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != want {
					t.Errorf("%s differs after round trip", name)
				}
				info, _ := os.Stat(filepath.Join(dst, filepath.FromSlash(name)))
				if info.Mode().Perm() != 0o600 {
					t.Errorf("%s mode = %o, want 600", name, info.Mode().Perm())
				}
			}
			if info, _ := os.Stat(dst); info.Mode().Perm() != 0o700 {
				t.Errorf("staging mode = %o, want 700", info.Mode().Perm())
			}
		})
	}
}

func TestOpenReportsManifest(t *testing.T) {
	archive, _ := build(t, testPass)
	r, err := Open(bytes.NewReader(archive), testPass)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Manifest
	if m.Format != ManifestFormat || m.FormatVersion != FormatVersion || !m.Encrypted || m.SchemaVersion != 15 {
		t.Errorf("manifest = %+v", m)
	}
}

func TestWrongPassphraseRejected(t *testing.T) {
	archive, _ := build(t, testPass)
	_, err := Open(bytes.NewReader(archive), []byte("wrong"))
	wantCode(t, err, errcode.BAKAuth001)
}

func TestEncryptedArchiveNeedsPassphrase(t *testing.T) {
	archive, _ := build(t, testPass)
	_, err := Open(bytes.NewReader(archive), nil)
	wantCode(t, err, errcode.BAKPass001)
}

func TestEmptyPassphraseRefusedOnWrite(t *testing.T) {
	_, err := NewWriter(&bytes.Buffer{}, testManifest(), []byte{}, testKDF)
	wantCode(t, err, errcode.BAKPass001)
}

func TestTamperedEncryptedArchiveRejected(t *testing.T) {
	archive, _ := build(t, testPass)
	for _, at := range []int{len(archive) / 2, len(archive) - 40} {
		tampered := bytes.Clone(archive)
		tampered[at] ^= 0x01
		_, err := extractTo(t, tampered, testPass, defaultOpts())
		wantCode(t, err, errcode.BAKAuth001)
	}
}

func TestTamperedHeaderRejected(t *testing.T) {
	archive, _ := build(t, testPass)
	tampered := bytes.Clone(archive)
	// The salt starts after the fixed header and the 9 bytes of KDF fields; changing it
	// changes the key, so the first frame fails authentication.
	tampered[fixedHeaderLen+9] ^= 0x01
	_, err := Open(bytes.NewReader(tampered), testPass)
	wantCode(t, err, errcode.BAKAuth001)
}

func TestTamperedPlainArchiveRejected(t *testing.T) {
	archive, _ := build(t, nil)
	tampered := bytes.Clone(archive)
	tampered[len(tampered)/2] ^= 0xff
	_, err := extractTo(t, tampered, nil, defaultOpts())
	if err == nil {
		t.Fatal("a corrupted plain archive was accepted")
	}
}

func TestTruncatedArchiveRejected(t *testing.T) {
	for _, pass := range [][]byte{testPass, nil} {
		archive, _ := build(t, pass)
		for _, cut := range []int{10, len(archive) / 2, len(archive) - 1} {
			_, err := extractTo(t, archive[:cut], pass, defaultOpts())
			if err == nil {
				t.Fatalf("archive cut to %d bytes (encrypted=%v) was accepted", cut, pass != nil)
			}
			if c := errcode.CodeOf(err); c != errcode.BAKTrunc001 && c != errcode.BAKFmt001 && c != errcode.BAKAuth001 {
				t.Errorf("cut to %d: code %q, want a truncation or format code", cut, c)
			}
		}
	}
}

func TestTruncatedEncryptedArchiveReportsTruncation(t *testing.T) {
	archive, _ := build(t, testPass)
	// Dropping whole trailing frames leaves a stream that never reaches its final frame.
	_, err := extractTo(t, archive[:len(archive)-tagSize-frameHeaderLen-1], testPass, defaultOpts())
	wantCode(t, err, errcode.BAKTrunc001)
}

func TestDataAfterFinalFrameRejected(t *testing.T) {
	archive, _ := build(t, testPass)
	_, err := extractTo(t, append(bytes.Clone(archive), 0x00), testPass, defaultOpts())
	wantCode(t, err, errcode.BAKFmt001)
}

func TestPathTraversalEntryRefused(t *testing.T) {
	for _, name := range []string{"../escape", "/etc/passwd", "a/../../b", "a//b", "./x", "a\\b"} {
		t.Run(name, func(t *testing.T) {
			archive := craft(t, nil, regEntry(name, "x"))
			dst, err := extractTo(t, archive, nil, defaultOpts())
			wantCode(t, err, errcode.BAKPath001)
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(dst), "escape")); statErr == nil {
				t.Fatal("entry escaped the staging directory")
			}
		})
	}
}

func TestSymlinkEntryRefused(t *testing.T) {
	archive := craft(t, testPass, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "nux.db", Linkname: "/etc/shadow", Mode: 0o777})
	})
	_, err := extractTo(t, archive, testPass, defaultOpts())
	wantCode(t, err, errcode.BAKPath001)
}

func TestHardLinkEntryRefused(t *testing.T) {
	archive := craft(t, nil, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "x", Linkname: "/etc/passwd"})
	})
	_, err := extractTo(t, archive, nil, defaultOpts())
	wantCode(t, err, errcode.BAKPath001)
}

func TestDuplicateEntryRefused(t *testing.T) {
	archive := craft(t, nil, regEntry("a", "1"), regEntry("a", "2"))
	_, err := extractTo(t, archive, nil, defaultOpts())
	wantCode(t, err, errcode.BAKPath001)
}

func TestWriterRefusesUnsafeNames(t *testing.T) {
	w, err := NewWriter(&bytes.Buffer{}, testManifest(), nil, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, w.AddFile("../x", 0, strings.NewReader("")), errcode.BAKPath001)
	wantCode(t, w.AddDir("/abs"), errcode.BAKPath001)
}

func TestNewerFormatVersionRefused(t *testing.T) {
	archive, _ := build(t, nil)
	tampered := bytes.Clone(archive)
	binary.BigEndian.PutUint16(tampered[len(magic):], FormatVersion+1)
	_, err := Open(bytes.NewReader(tampered), nil)
	wantCode(t, err, errcode.BAKVer001)
}

func TestNewerSchemaRefusedBeforeWriting(t *testing.T) {
	m := testManifest()
	m.SchemaVersion = 16
	var buf bytes.Buffer
	w, err := NewWriter(&buf, m, nil, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "staging")
	_, err = r.Extract(dst, ExtractOptions{MaxSchemaVersion: 15})
	wantCode(t, err, errcode.BAKVer001)
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("staging directory was created for a refused archive")
	}
}

func TestChecksumMismatchRefused(t *testing.T) {
	// Write a file whose recorded checksum does not match its content.
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testManifest(), nil, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile("nux.db", 3, strings.NewReader("abc")); err != nil {
		t.Fatal(err)
	}
	w.sums[0].SHA256 = hex.EncodeToString(sha256.New().Sum(nil))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = extractTo(t, buf.Bytes(), nil, defaultOpts())
	wantCode(t, err, errcode.BAKHash001)
}

func TestFileMissingFromChecksumsRefused(t *testing.T) {
	archive := craft(t, nil, regEntry("extra", "x"))
	_, err := extractTo(t, archive, nil, defaultOpts())
	wantCode(t, err, errcode.BAKHash001)
}

func TestArchiveWithoutChecksumsRefused(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testManifest(), nil, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.gz.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = extractTo(t, buf.Bytes(), nil, defaultOpts())
	wantCode(t, err, errcode.BAKTrunc001)
}

func TestZipBombLimitsEnforced(t *testing.T) {
	archive, _ := build(t, nil)
	opts := ExtractOptions{MaxSchemaVersion: 15, Limits: Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 10, MaxEntries: 100}}
	_, err := extractTo(t, archive, nil, opts)
	wantCode(t, err, errcode.BAKLimit001)

	opts = ExtractOptions{MaxSchemaVersion: 15, Limits: Limits{MaxFileBytes: 10, MaxTotalBytes: 1 << 30, MaxEntries: 100}}
	_, err = extractTo(t, archive, nil, opts)
	wantCode(t, err, errcode.BAKLimit001)

	opts = ExtractOptions{MaxSchemaVersion: 15, Limits: Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 30, MaxEntries: 1}}
	_, err = extractTo(t, archive, nil, opts)
	wantCode(t, err, errcode.BAKLimit001)
}

func TestExtractRefusesNonEmptyTarget(t *testing.T) {
	archive, _ := build(t, nil)
	r, err := Open(bytes.NewReader(archive), nil)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "existing"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = r.Extract(dst, defaultOpts())
	wantCode(t, err, errcode.BAKRest001)
}

func TestNotAnArchive(t *testing.T) {
	_, err := Open(strings.NewReader("hello world, this is not a backup"), nil)
	wantCode(t, err, errcode.BAKFmt001)
}
