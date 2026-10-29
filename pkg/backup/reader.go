// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Limits bound what an archive may expand to, so a crafted archive cannot fill the disk.
type Limits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxEntries    int
}

// DefaultLimits are generous for a real data directory and far below a disk-filling bomb.
var DefaultLimits = Limits{MaxFileBytes: 64 << 30, MaxTotalBytes: 256 << 30, MaxEntries: 1 << 20}

// ExtractOptions controls Reader.Extract.
type ExtractOptions struct {
	// MaxSchemaVersion is the newest database schema this build understands. Archives with
	// a newer schema are refused before anything is written.
	MaxSchemaVersion int
	// Limits overrides DefaultLimits when non-zero.
	Limits Limits
}

// Reader opens an archive and extracts it. Open validates the header and manifest, so the
// caller can decide before any payload is written.
type Reader struct {
	Manifest Manifest

	gz   *gzip.Reader
	body io.Reader
	tr   *tar.Reader
}

// Open reads the archive header and manifest. A nil passphrase is only valid for an
// unencrypted archive; for an encrypted one a wrong passphrase fails here with BAK-AUTH-001.
// A passphrase given for an unencrypted archive is ignored.
func Open(in io.Reader, passphrase []byte) (*Reader, error) {
	br := bufio.NewReaderSize(in, chunkSize)
	h, raw, err := readHeader(br)
	if err != nil {
		return nil, err
	}

	var body io.Reader = br
	if h.encrypted {
		if len(passphrase) == 0 {
			return nil, errcode.New(errcode.BAKPass001, "this archive is encrypted; pass --passphrase-file, or --master-key-file for a pre-upgrade archive")
		}
		aead, err := deriveAEAD(passphrase, h)
		if err != nil {
			return nil, err
		}
		body = newOpenReader(br, aead, raw, h.noncePrefix)
	}

	gz, err := gzip.NewReader(body)
	if err != nil {
		return nil, classifyStream(err, "open compression")
	}
	r := &Reader{gz: gz, body: body, tr: tar.NewReader(gz)}

	hdr, err := r.tr.Next()
	if err != nil {
		return nil, classifyStream(err, "read manifest")
	}
	if hdr.Name != manifestName || hdr.Typeflag != tar.TypeReg {
		return nil, errcode.New(errcode.BAKFmt001, "the first entry must be %s", manifestName)
	}
	if err := json.NewDecoder(io.LimitReader(r.tr, maxMetaBytes)).Decode(&r.Manifest); err != nil {
		return nil, classifyStream(err, "decode manifest")
	}
	if r.Manifest.Format != ManifestFormat || r.Manifest.FormatVersion != int(h.version) || r.Manifest.Encrypted != h.encrypted {
		return nil, errcode.New(errcode.BAKFmt001, "manifest does not match the archive header")
	}
	return r, nil
}

// Extract writes the payload into dir, which must not exist or be empty. Every file is
// checked against checksums.json before Extract returns nil, so a successful return means
// the whole archive was authenticated (when encrypted) and every hash matched. The caller
// swaps dir into place only after that.
func (r *Reader) Extract(dir string, opts ExtractOptions) (Manifest, error) {
	if r.Manifest.SchemaVersion > opts.MaxSchemaVersion {
		return Manifest{}, errcode.New(errcode.BAKVer001, "archive schema version %d is newer than this build's %d; restore it with a newer nuxd", r.Manifest.SchemaVersion, opts.MaxSchemaVersion)
	}
	limits := opts.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits
	}
	if err := prepareTarget(dir); err != nil {
		return Manifest{}, err
	}

	x := &extraction{dir: dir, limits: limits, written: map[string]Checksum{}}
	for {
		hdr, err := r.tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, classifyStream(err, "read entry")
		}
		if x.sawChecksums {
			return Manifest{}, errcode.New(errcode.BAKPath001, "entry %q follows the checksum list", hdr.Name)
		}
		x.entries++
		if x.entries > limits.MaxEntries {
			return Manifest{}, errcode.New(errcode.BAKLimit001, "archive has more than %d entries", limits.MaxEntries)
		}
		if err := x.entry(r.tr, hdr); err != nil {
			return Manifest{}, err
		}
	}
	if !x.sawChecksums {
		return Manifest{}, errcode.New(errcode.BAKTrunc001, "archive ends before %s", checksumsName)
	}
	if err := x.verify(); err != nil {
		return Manifest{}, err
	}
	if err := r.drain(); err != nil {
		return Manifest{}, err
	}
	return r.Manifest, nil
}

// drain reads the rest of the decompressed stream and then the rest of the input. Reading
// the gzip stream to its end verifies the gzip checksum, and reading the encrypted body to
// its end verifies the final frame. Only tar padding may remain inside the compressed
// stream, and nothing may follow it. The limit stops a padding bomb from hiding behind it.
func (r *Reader) drain() error {
	const maxPadding = 1 << 20
	n, err := io.CopyN(io.Discard, r.gz, maxPadding+1)
	if n > maxPadding {
		return errcode.New(errcode.BAKLimit001, "archive has more than %d bytes of padding after its last entry", maxPadding)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return classifyStream(err, "finish compression")
	}
	n, err = io.CopyN(io.Discard, r.body, 1)
	if n > 0 {
		return errcode.New(errcode.BAKFmt001, "archive has data after its last entry")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return classifyStream(err, "finish archive")
	}
	return nil
}

// Close releases the decompressor. It does not close the underlying reader.
func (r *Reader) Close() error {
	return r.gz.Close()
}

type extraction struct {
	dir          string
	limits       Limits
	entries      int
	total        int64
	written      map[string]Checksum
	expected     []Checksum
	sawChecksums bool
}

func (x *extraction) entry(tr *tar.Reader, hdr *tar.Header) error {
	switch hdr.Typeflag {
	case tar.TypeSymlink, tar.TypeLink:
		return errcode.New(errcode.BAKPath001, "entry %q is a link; links are not allowed", hdr.Name)
	case tar.TypeDir:
		if err := ValidateName(strings.TrimSuffix(hdr.Name, "/")); err != nil {
			return err
		}
		return os.MkdirAll(filepath.Join(x.dir, filepath.FromSlash(strings.TrimSuffix(hdr.Name, "/"))), 0o700)
	case tar.TypeReg:
	default:
		return errcode.New(errcode.BAKPath001, "entry %q has type %q; only files and directories are allowed", hdr.Name, hdr.Typeflag)
	}

	if hdr.Name == checksumsName {
		return x.readChecksums(tr)
	}
	if err := ValidateName(hdr.Name); err != nil {
		return err
	}
	if _, dup := x.written[hdr.Name]; dup {
		return errcode.New(errcode.BAKPath001, "entry %q is listed twice", hdr.Name)
	}
	if hdr.Size < 0 || hdr.Size > x.limits.MaxFileBytes {
		return errcode.New(errcode.BAKLimit001, "entry %q is %d bytes; the limit is %d", hdr.Name, hdr.Size, x.limits.MaxFileBytes)
	}
	if x.total+hdr.Size > x.limits.MaxTotalBytes {
		return errcode.New(errcode.BAKLimit001, "archive expands past the %d byte limit", x.limits.MaxTotalBytes)
	}
	x.total += hdr.Size

	target := filepath.Join(x.dir, filepath.FromSlash(hdr.Name))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return errcode.Wrap(errcode.BAKRest001, "create directory for "+hdr.Name, err)
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // target is validated and inside x.dir
	if err != nil {
		return errcode.Wrap(errcode.BAKRest001, "create "+hdr.Name, err)
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, hash), tr)
	closeErr := f.Close()
	if copyErr != nil {
		return classifyStream(copyErr, "write "+hdr.Name)
	}
	if closeErr != nil {
		return errcode.Wrap(errcode.BAKRest001, "write "+hdr.Name, closeErr)
	}
	if n != hdr.Size {
		return errcode.New(errcode.BAKTrunc001, "entry %q ended after %d of %d bytes", hdr.Name, n, hdr.Size)
	}
	x.written[hdr.Name] = Checksum{Path: hdr.Name, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))}
	return nil
}

func (x *extraction) readChecksums(tr *tar.Reader) error {
	var list checksums
	data, err := io.ReadAll(io.LimitReader(tr, maxMetaBytes+1))
	if err != nil {
		return classifyStream(err, "read "+checksumsName)
	}
	if len(data) > maxMetaBytes {
		return errcode.New(errcode.BAKLimit001, "%s is larger than %d bytes", checksumsName, maxMetaBytes)
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "decode "+checksumsName, err)
	}
	for _, c := range list.Files {
		if err := ValidateName(c.Path); err != nil {
			return err
		}
	}
	x.expected = list.Files
	x.sawChecksums = true
	return nil
}

// verify compares every extracted file with the checksum list. A file missing from the list
// or a listed file missing from the archive is a mismatch.
func (x *extraction) verify() error {
	if len(x.expected) != len(x.written) {
		return errcode.New(errcode.BAKHash001, "checksum list has %d files but the archive holds %d", len(x.expected), len(x.written))
	}
	for _, want := range x.expected {
		got, ok := x.written[want.Path]
		if !ok {
			return errcode.New(errcode.BAKHash001, "%s is listed in the checksums but missing from the archive", want.Path)
		}
		if got.Size != want.Size || got.SHA256 != strings.ToLower(want.SHA256) {
			return errcode.New(errcode.BAKHash001, "%s does not match its recorded checksum", want.Path)
		}
	}
	return nil
}

// prepareTarget requires dir to be absent or empty and creates it private to the user.
func prepareTarget(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return errcode.Wrap(errcode.BAKRest001, "inspect restore target", err)
	case len(entries) > 0:
		return errcode.New(errcode.BAKRest001, "restore staging directory %s is not empty", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errcode.Wrap(errcode.BAKRest001, "create restore staging directory", err)
	}
	return os.Chmod(dir, 0o700) //nolint:gosec // a directory needs the execute bit
}

// classifyStream maps read failures to codes: end-of-input is truncation, anything the
// decompressor or tar parser rejects is a malformed archive, and coded errors pass through.
func classifyStream(err error, what string) error {
	if errcode.CodeOf(err) != "" {
		return err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errcode.Wrap(errcode.BAKTrunc001, what, err)
	}
	return errcode.New(errcode.BAKFmt001, "%s: %v", what, err)
}
