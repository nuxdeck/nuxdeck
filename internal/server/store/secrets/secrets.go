// SPDX-License-Identifier: AGPL-3.0-only

// Package secrets stores credentials that users give nuxd (SMTP passwords, webhook URLs,
// check credentials, TOTP seeds) encrypted at rest (T7).
//
// Each secret is sealed with AES-256-GCM under its own random data key (DEK); the DEK is
// in turn sealed under the master key. Both seals use the secret's id as associated data,
// so a row copied onto another id fails authentication. Every call takes the caller's
// *sql.Tx, so an owning row's secret_ref and its audit entry commit or roll back together
// with the secret itself.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

// KeyLen is the size in bytes of the master key and of every data key.
const KeyLen = 32

// formatV1 is the first byte of wrapped_dek: version 1 = nonce(12) || AES-256-GCM(DEK).
// Master key rotation will add a version (and, if needed, a key id) here; none is built yet.
const formatV1 byte = 1

const wrappedV1Len = 1 + 12 + KeyLen + 16

// ErrNotFound is returned when no secret has the given id.
var ErrNotFound = errors.New("secret not found")

// DB is the part of *sql.Tx (and *sql.DB) that the package needs. Pass the caller's
// transaction to make the secret part of it.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Box seals and opens secrets under one master key. It is safe for concurrent use.
type Box struct {
	master cipher.AEAD
	now    func() time.Time
	rand   io.Reader
}

// New builds a Box. masterKey must be KeyLen bytes; New keeps no reference to it.
func New(masterKey []byte) (*Box, error) {
	if len(masterKey) != KeyLen {
		return nil, errcode.New(errcode.SRVSec001, "master key must be %d bytes, got %d", KeyLen, len(masterKey))
	}
	aead, err := newGCM(masterKey)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVSec001, "master key", err)
	}
	return &Box{master: aead, now: time.Now, rand: rand.Reader}, nil
}

// SetClock replaces the clock used for created_at; for tests.
func (b *Box) SetClock(now func() time.Time) { b.now = now }

// Put encrypts plaintext and stores it, returning the new secret's id. The caller keeps
// ownership of plaintext and may zero it afterwards.
func (b *Box) Put(ctx context.Context, q DB, plaintext []byte) (string, error) {
	id, err := ids.New()
	if err != nil {
		return "", fmt.Errorf("create secret id: %w", err)
	}
	ct, nonce, wrapped, err := b.seal(id, plaintext)
	if err != nil {
		return "", err
	}
	if _, err := q.ExecContext(ctx,
		`INSERT INTO secrets (id, ciphertext, nonce, wrapped_dek, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, ct, nonce, wrapped, b.now().UnixMilli()); err != nil {
		return "", fmt.Errorf("store secret: %w", err)
	}
	return id, nil
}

// Get returns the plaintext of a secret. The caller should zero it after use. It returns
// ErrNotFound for an unknown id and an SRV-SEC-002 error if the row fails authentication.
func (b *Box) Get(ctx context.Context, q DB, id string) ([]byte, error) {
	var ct, nonce, wrapped []byte
	err := q.QueryRowContext(ctx, `SELECT ciphertext, nonce, wrapped_dek FROM secrets WHERE id = ?`, id).Scan(&ct, &nonce, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return b.open(id, ct, nonce, wrapped)
}

// Replace seals plaintext under a fresh data key and nonces and overwrites the row,
// keeping its id and created_at. It returns ErrNotFound for an unknown id.
func (b *Box) Replace(ctx context.Context, q DB, id string, plaintext []byte) error {
	ct, nonce, wrapped, err := b.seal(id, plaintext)
	if err != nil {
		return err
	}
	res, err := q.ExecContext(ctx, `UPDATE secrets SET ciphertext = ?, nonce = ?, wrapped_dek = ? WHERE id = ?`, ct, nonce, wrapped, id)
	if err != nil {
		return fmt.Errorf("replace secret: %w", err)
	}
	return expectOne(res)
}

// Delete removes a secret. It returns ErrNotFound for an unknown id.
func (b *Box) Delete(ctx context.Context, q DB, id string) error {
	res, err := q.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return expectOne(res)
}

// Any reports whether the table holds at least one secret. nuxd uses it to refuse a
// freshly generated master key on a database that already has sealed secrets.
func Any(ctx context.Context, q DB) (bool, error) {
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM secrets LIMIT 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("count secrets: %w", err)
	}
	return true, nil
}

func expectOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// aad binds a seal to its purpose and row. The purpose keeps a DEK blob from ever
// authenticating as data, and the other way round.
func aad(purpose, id string) []byte { return []byte("nuxd/secret/v1/" + purpose + "/" + id) }

func (b *Box) seal(id string, plaintext []byte) (ciphertext, nonce, wrapped []byte, err error) {
	dek := make([]byte, KeyLen)
	defer clear(dek)
	if _, err = io.ReadFull(b.rand, dek); err != nil {
		return nil, nil, nil, fmt.Errorf("generate data key: %w", err)
	}
	dataAEAD, err := newGCM(dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("data key: %w", err)
	}
	if nonce, err = b.nonce(dataAEAD); err != nil {
		return nil, nil, nil, err
	}
	ciphertext = dataAEAD.Seal(nil, nonce, plaintext, aad("data", id)) //nolint:gosec // G407 false positive: nonce is random per call (b.nonce)

	wrapNonce, err := b.nonce(b.master)
	if err != nil {
		return nil, nil, nil, err
	}
	wrapped = append([]byte{formatV1}, wrapNonce...)
	wrapped = b.master.Seal(wrapped, wrapNonce, dek, aad("dek", id))
	return ciphertext, nonce, wrapped, nil
}

func (b *Box) open(id string, ciphertext, nonce, wrapped []byte) ([]byte, error) {
	fail := func(why string) error {
		return errcode.New(errcode.SRVSec002, "secret %s: %s", id, why)
	}
	if len(wrapped) == 0 || wrapped[0] != formatV1 || len(wrapped) != wrappedV1Len {
		return nil, fail("unsupported or damaged wrapped key")
	}
	ns := b.master.NonceSize()
	dek, err := b.master.Open(nil, wrapped[1:1+ns], wrapped[1+ns:], aad("dek", id))
	if err != nil {
		return nil, fail("data key failed authentication")
	}
	defer clear(dek)
	dataAEAD, err := newGCM(dek)
	if err != nil {
		return nil, fail("data key unusable")
	}
	if len(nonce) != dataAEAD.NonceSize() {
		return nil, fail("damaged nonce")
	}
	plaintext, err := dataAEAD.Open(nil, nonce, ciphertext, aad("data", id))
	if err != nil {
		return nil, fail("ciphertext failed authentication")
	}
	return plaintext, nil
}

func (b *Box) nonce(a cipher.AEAD) ([]byte, error) {
	n := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(b.rand, n); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return n, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
