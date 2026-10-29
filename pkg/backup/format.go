// SPDX-License-Identifier: Apache-2.0

// Package backup reads and writes Nux Deck backup archives: a gzip-compressed tar stream,
// optionally sealed in authenticated chunks with AES-256-GCM under a key derived from a
// passphrase with Argon2id.
//
// Layout, in order:
//
//	header      plaintext magic, format version, flags and, when encrypted, the KDF salt,
//	            cost parameters and nonce prefix. The header is authenticated as AAD.
//	frames      (encrypted only) 64 KiB plaintext chunks, each sealed with AES-256-GCM.
//	            The last frame carries a final flag; a stream that ends without one is
//	            truncated.
//	gzip(tar)   first entry manifest.json (metadata), then the payload files, then
//	            checksums.json (SHA-256 and size of every payload file).
//
// The package has no dependency on the server. Its only job is the format, so the server
// and tooling share one implementation and one set of safety checks.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// FormatVersion is the archive layout this package writes. Readers refuse newer versions.
const FormatVersion = 1

// ManifestFormat is the value of Manifest.Format in every archive.
const ManifestFormat = "nuxd-backup"

const (
	magic          = "NUXBAK"
	flagEncrypted  = 1
	chunkSize      = 64 << 10
	tagSize        = 16
	saltLen        = 16
	noncePrefixLen = 8
	nonceLen       = 12 // AES-GCM: 8-byte random prefix and a 4-byte frame counter
	keyLen         = 32
	frameMore      = 0
	frameFinal     = 1
	frameHeaderLen = 5
	fixedHeaderLen = len(magic) + 2 + 1
	kdfFieldsLen   = 4 + 4 + 1 + saltLen + noncePrefixLen
	maxKDFMemory   = 1 << 20 // KiB, 1 GiB
	maxKDFTime     = 10
	maxKDFThreads  = 32
)

// KDF holds the Argon2id cost parameters of an encrypted archive. They are stored in the
// header, so the defaults can be raised later without breaking restore of old archives.
type KDF struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultKDF follows the second recommended profile in RFC 9106.
var DefaultKDF = KDF{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

func (k KDF) validate() error {
	if k.Time < 1 || k.Time > maxKDFTime || k.Threads < 1 || k.Threads > maxKDFThreads ||
		k.MemoryKiB < 8*uint32(k.Threads) || k.MemoryKiB > maxKDFMemory {
		return errcode.New(errcode.BAKFmt001, "unsupported key derivation parameters")
	}
	return nil
}

type header struct {
	version     uint16
	encrypted   bool
	kdf         KDF
	salt        [saltLen]byte
	noncePrefix [noncePrefixLen]byte
}

func (h header) marshal() []byte {
	b := make([]byte, 0, fixedHeaderLen+kdfFieldsLen)
	b = append(b, magic...)
	b = binary.BigEndian.AppendUint16(b, h.version)
	if !h.encrypted {
		return append(b, 0)
	}
	b = append(b, flagEncrypted)
	b = binary.BigEndian.AppendUint32(b, h.kdf.Time)
	b = binary.BigEndian.AppendUint32(b, h.kdf.MemoryKiB)
	b = append(b, h.kdf.Threads)
	b = append(b, h.salt[:]...)
	return append(b, h.noncePrefix[:]...)
}

// readHeader parses the plaintext header and returns its raw bytes, which every frame
// authenticates.
func readHeader(r io.Reader) (header, []byte, error) {
	var h header
	fixed := make([]byte, fixedHeaderLen)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return h, nil, classifyRead(err, "read archive header")
	}
	if string(fixed[:len(magic)]) != magic {
		return h, nil, errcode.New(errcode.BAKFmt001, "the file does not start with the Nux Deck backup magic")
	}
	h.version = binary.BigEndian.Uint16(fixed[len(magic):])
	if h.version == 0 {
		return h, nil, errcode.New(errcode.BAKFmt001, "archive format version 0 is not valid")
	}
	if h.version > FormatVersion {
		return h, nil, errcode.New(errcode.BAKVer001, "archive format %d is newer than the supported %d", h.version, FormatVersion)
	}
	flags := fixed[len(fixed)-1]
	if flags&^flagEncrypted != 0 {
		return h, nil, errcode.New(errcode.BAKFmt001, "archive header has unknown flags %#x", flags)
	}
	if flags&flagEncrypted == 0 {
		return h, fixed, nil
	}

	rest := make([]byte, kdfFieldsLen)
	if _, err := io.ReadFull(r, rest); err != nil {
		return h, nil, classifyRead(err, "read archive key parameters")
	}
	h.encrypted = true
	h.kdf = KDF{
		Time:      binary.BigEndian.Uint32(rest[0:4]),
		MemoryKiB: binary.BigEndian.Uint32(rest[4:8]),
		Threads:   rest[8],
	}
	if err := h.kdf.validate(); err != nil {
		return h, nil, err
	}
	copy(h.salt[:], rest[9:9+saltLen])
	copy(h.noncePrefix[:], rest[9+saltLen:])
	return h, append(fixed, rest...), nil
}

// deriveAEAD turns the passphrase into an AES-256-GCM instance. Argon2id is memory-hard,
// so a stolen archive cannot be attacked cheaply with GPUs.
func deriveAEAD(passphrase []byte, h header) (cipher.AEAD, error) {
	key := argon2.IDKey(passphrase, h.salt[:], h.kdf.Time, h.kdf.MemoryKiB, h.kdf.Threads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errcode.Wrap(errcode.BAKFmt001, "create cipher", err)
	}
	return cipher.NewGCM(block)
}

func frameNonce(prefix [noncePrefixLen]byte, counter uint32) []byte {
	n := make([]byte, nonceLen)
	copy(n, prefix[:])
	binary.BigEndian.PutUint32(n[noncePrefixLen:], counter)
	return n
}

// frameAAD binds each frame to the header and to its own final flag, so frames cannot be
// reordered, dropped from the end, or spliced between archives.
func frameAAD(rawHeader []byte, flag byte) []byte {
	aad := make([]byte, 0, len(rawHeader)+1)
	aad = append(aad, rawHeader...)
	return append(aad, flag)
}

// sealWriter encrypts a stream in frames. Close must be called to emit the final frame.
type sealWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	header  []byte
	prefix  [noncePrefixLen]byte
	counter uint32
	buf     []byte
	closed  bool
}

func newSealWriter(w io.Writer, aead cipher.AEAD, rawHeader []byte, prefix [noncePrefixLen]byte) *sealWriter {
	return &sealWriter{w: w, aead: aead, header: rawHeader, prefix: prefix, buf: make([]byte, 0, chunkSize)}
}

func (s *sealWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("backup: write after close")
	}
	written := 0
	for len(p) > 0 {
		n := min(chunkSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(s.buf) == chunkSize {
			if err := s.emit(frameMore); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (s *sealWriter) emit(flag byte) error {
	if s.counter == ^uint32(0) {
		return errors.New("backup: archive exceeds the maximum number of frames")
	}
	ct := s.aead.Seal(nil, frameNonce(s.prefix, s.counter), s.buf, frameAAD(s.header, flag))
	frame := make([]byte, frameHeaderLen, frameHeaderLen+len(ct))
	frame[0] = flag
	binary.BigEndian.PutUint32(frame[1:], uint32(len(ct))) //nolint:gosec // bounded by chunkSize+tagSize
	frame = append(frame, ct...)
	if _, err := s.w.Write(frame); err != nil {
		return err
	}
	s.counter++
	s.buf = s.buf[:0]
	return nil
}

// Close writes the final frame. It does not close the underlying writer.
func (s *sealWriter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.emit(frameFinal)
}

// openReader decrypts a framed stream. It returns io.EOF only after the verified final
// frame, and reports truncation or trailing data as errors.
type openReader struct {
	r       io.ByteReader
	src     io.Reader
	aead    cipher.AEAD
	header  []byte
	prefix  [noncePrefixLen]byte
	counter uint32
	plain   []byte
	done    bool
	ct      []byte
}

func newOpenReader(src io.Reader, aead cipher.AEAD, rawHeader []byte, prefix [noncePrefixLen]byte) *openReader {
	return &openReader{r: byteReader(src), src: src, aead: aead, header: rawHeader, prefix: prefix}
}

func (o *openReader) Read(p []byte) (int, error) {
	for len(o.plain) == 0 {
		if o.done {
			return 0, io.EOF
		}
		if err := o.nextFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, o.plain)
	o.plain = o.plain[n:]
	return n, nil
}

func (o *openReader) nextFrame() error {
	var fh [frameHeaderLen]byte
	if _, err := io.ReadFull(o.src, fh[:]); err != nil {
		return classifyRead(err, "read archive frame")
	}
	flag := fh[0]
	if flag != frameMore && flag != frameFinal {
		return errcode.New(errcode.BAKFmt001, "archive frame has unknown flag %d", flag)
	}
	n := binary.BigEndian.Uint32(fh[1:])
	if n < tagSize || n > chunkSize+tagSize {
		return errcode.New(errcode.BAKFmt001, "archive frame of %d bytes is out of range", n)
	}
	if cap(o.ct) < int(n) {
		o.ct = make([]byte, n)
	}
	ct := o.ct[:n]
	if _, err := io.ReadFull(o.src, ct); err != nil {
		return classifyRead(err, "read archive frame")
	}
	pt, err := o.aead.Open(nil, frameNonce(o.prefix, o.counter), ct, frameAAD(o.header, flag))
	if err != nil {
		return errcode.New(errcode.BAKAuth001, "frame %d failed authentication", o.counter)
	}
	o.counter++
	o.plain = pt
	if flag == frameFinal {
		o.done = true
		if _, err := o.r.ReadByte(); err == nil {
			return errcode.New(errcode.BAKFmt001, "archive has data after its final frame")
		} else if !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}

type byteReaderFunc struct{ io.Reader }

func (b byteReaderFunc) ReadByte() (byte, error) {
	var one [1]byte
	_, err := io.ReadFull(b.Reader, one[:])
	return one[0], err
}

func byteReader(r io.Reader) io.ByteReader {
	if br, ok := r.(io.ByteReader); ok {
		return br
	}
	return byteReaderFunc{r}
}

// classifyRead maps an end-of-input error to BAK-TRUNC-001 and passes other errors through.
func classifyRead(err error, what string) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errcode.Wrap(errcode.BAKTrunc001, what, err)
	}
	return err
}
