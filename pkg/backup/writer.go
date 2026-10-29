// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const (
	manifestName  = "manifest.json"
	checksumsName = "checksums.json"
	maxMetaBytes  = 16 << 20
)

// Manifest describes an archive. The writer fills in Format, FormatVersion and Encrypted;
// the caller supplies the rest.
type Manifest struct {
	Format        string    `json:"format"`
	FormatVersion int       `json:"format_version"`
	NuxdVersion   string    `json:"nuxd_version"`
	CreatedAt     time.Time `json:"created_at"`
	// SchemaVersion is the highest database migration applied in the archived data.
	SchemaVersion int  `json:"schema_version"`
	Encrypted     bool `json:"encrypted"`
	// MasterKeyIncluded reports whether the archive holds the secrets master key.
	MasterKeyIncluded bool `json:"master_key_included"`
}

// Checksum is the recorded identity of one payload file.
type Checksum struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type checksums struct {
	Files []Checksum `json:"files"`
}

// Writer streams an archive. Add entries in any order, then call Close. Nothing is
// buffered beyond one encryption chunk, so memory stays bounded however large the data.
type Writer struct {
	gz      *gzip.Writer
	tw      *tar.Writer
	seal    *sealWriter
	modTime time.Time
	sums    []Checksum
	seen    map[string]bool
	closed  bool
}

// NewWriter writes the header and manifest to out. A nil passphrase writes an unencrypted
// archive; an empty non-nil one is refused. kdf may be the zero value for DefaultKDF.
func NewWriter(out io.Writer, m Manifest, passphrase []byte, kdf KDF) (*Writer, error) {
	h := header{version: FormatVersion, encrypted: passphrase != nil}
	body := out
	var seal *sealWriter
	if h.encrypted {
		if len(passphrase) == 0 {
			return nil, errcode.New(errcode.BAKPass001, "the passphrase is empty")
		}
		if kdf == (KDF{}) {
			kdf = DefaultKDF
		}
		if err := kdf.validate(); err != nil {
			return nil, err
		}
		h.kdf = kdf
		if _, err := io.ReadFull(rand.Reader, h.salt[:]); err != nil {
			return nil, errcode.Wrap(errcode.BAKFmt001, "generate salt", err)
		}
		if _, err := io.ReadFull(rand.Reader, h.noncePrefix[:]); err != nil {
			return nil, errcode.Wrap(errcode.BAKFmt001, "generate nonce prefix", err)
		}
		aead, err := deriveAEAD(passphrase, h)
		if err != nil {
			return nil, err
		}
		raw := h.marshal()
		if _, err := out.Write(raw); err != nil {
			return nil, err
		}
		seal = newSealWriter(out, aead, raw, h.noncePrefix)
		body = seal
	} else if _, err := out.Write(h.marshal()); err != nil {
		return nil, err
	}

	m.Format = ManifestFormat
	m.FormatVersion = FormatVersion
	m.Encrypted = h.encrypted
	gz, err := gzip.NewWriterLevel(body, gzip.DefaultCompression)
	if err != nil {
		return nil, errcode.Wrap(errcode.BAKFmt001, "start compression", err)
	}
	w := &Writer{gz: gz, tw: tar.NewWriter(gz), seal: seal, modTime: m.CreatedAt.UTC(), seen: map[string]bool{manifestName: true, checksumsName: true}}
	if err := w.writeJSON(manifestName, m); err != nil {
		return nil, err
	}
	return w, nil
}

// AddDir records a directory entry. Restore creates directories itself, so this only
// keeps the archive's layout explicit.
func (w *Writer) AddDir(name string) error {
	if err := w.reserve(name); err != nil {
		return err
	}
	return w.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o700, ModTime: w.modTime})
}

// AddFile copies exactly size bytes from r into the archive as name. The caller obtains
// size from the file's stat under the data-directory lock, so the file cannot change under
// the copy; a short read is an error.
func (w *Writer) AddFile(name string, size int64, r io.Reader) error {
	if size < 0 {
		return errcode.New(errcode.BAKSrc001, "file %s has a negative size", name)
	}
	if err := w.reserve(name); err != nil {
		return err
	}
	if err := w.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: size, ModTime: w.modTime}); err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "write entry "+name, err)
	}
	hash := sha256.New()
	n, err := io.CopyN(io.MultiWriter(w.tw, hash), r, size)
	if err != nil {
		return errcode.Wrap(errcode.BAKSrc001, fmt.Sprintf("copy %s (%d of %d bytes)", name, n, size), err)
	}
	w.sums = append(w.sums, Checksum{Path: name, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))})
	return nil
}

// Close writes the checksum list and the final frame. The caller owns out and closes it.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.writeJSON(checksumsName, checksums{Files: w.sums}); err != nil {
		return err
	}
	if err := w.tw.Close(); err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "finish archive", err)
	}
	if err := w.gz.Close(); err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "finish compression", err)
	}
	if w.seal != nil {
		return w.seal.Close()
	}
	return nil
}

func (w *Writer) reserve(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if w.seen[name] {
		return errcode.New(errcode.BAKPath001, "entry %q is listed twice", name)
	}
	w.seen[name] = true
	return nil
}

func (w *Writer) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "encode "+name, err)
	}
	if err := w.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: w.modTime}); err != nil {
		return errcode.Wrap(errcode.BAKFmt001, "write entry "+name, err)
	}
	_, err = w.tw.Write(data)
	return err
}

// ValidateName accepts only clean, relative, slash-separated paths with no empty, "." or
// ".." element. Writers and readers both apply it, so a restore never leaves its target.
func ValidateName(name string) error {
	if name == "" || len(name) > 1024 || strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
		return errcode.New(errcode.BAKPath001, "entry name %q is not a relative path", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return errcode.New(errcode.BAKPath001, "entry name %q has an empty, current or parent element", name)
		}
	}
	if path.Clean(name) != name {
		return errcode.New(errcode.BAKPath001, "entry name %q is not clean", name)
	}
	return nil
}
