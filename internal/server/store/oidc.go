// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

// oidcProviderID is the row of the single provider v0.1 supports.
const oidcProviderID = 1

var _ auth.OIDCRepository = (*Store)(nil)

// OIDCProvider reads the provider settings, or auth.ErrNotFound when none are configured.
func (s *Store) OIDCProvider(ctx context.Context) (auth.OIDCProvider, error) {
	var p auth.OIDCProvider
	var scopesJSON, domainsJSON string
	var autoProvision, linkExisting int
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT issuer, client_id, scopes_json, groups_claim, allowed_domains_json, auto_provision, link_existing, updated_at
		FROM oidc_providers WHERE id = ?`, oidcProviderID).
		Scan(&p.Issuer, &p.ClientID, &scopesJSON, &p.GroupsClaim, &domainsJSON, &autoProvision, &linkExisting, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.OIDCProvider{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.OIDCProvider{}, fmt.Errorf("read sso settings: %w", err)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &p.Scopes); err != nil {
		return auth.OIDCProvider{}, fmt.Errorf("decode sso scopes: %w", err)
	}
	if err := json.Unmarshal([]byte(domainsJSON), &p.AllowedDomains); err != nil {
		return auth.OIDCProvider{}, fmt.Errorf("decode sso domains: %w", err)
	}
	p.AutoProvision, p.LinkExisting = autoProvision == 1, linkExisting == 1
	p.UpdatedAt = time.UnixMilli(updated)
	return p, nil
}

// OIDCClientSecret opens the stored client secret. It is used only to talk to the provider.
func (s *Store) OIDCClientSecret(ctx context.Context) (string, error) {
	if s.secretBox == nil {
		return "", errors.New("secrets are not configured")
	}
	var ref string
	err := s.db.QueryRowContext(ctx, `SELECT client_secret_ref FROM oidc_providers WHERE id = ?`, oidcProviderID).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return "", auth.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read client secret reference: %w", err)
	}
	secret, err := s.secretBox.Get(ctx, s.db, ref)
	if err != nil {
		return "", fmt.Errorf("open client secret: %w", err)
	}
	return string(secret), nil
}

// SaveOIDCProvider stores the settings and the audit entry together. An empty secret keeps the
// stored one; the first save must carry one.
func (s *Store) SaveOIDCProvider(ctx context.Context, p auth.OIDCProvider, secret string, ev audit.Event) error {
	if s.secretBox == nil {
		return errors.New("secrets are not configured")
	}
	scopes, err := json.Marshal(p.Scopes)
	if err != nil {
		return fmt.Errorf("encode sso scopes: %w", err)
	}
	domains, err := json.Marshal(p.AllowedDomains)
	if err != nil {
		return fmt.Errorf("encode sso domains: %w", err)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var ref string
		err := tx.QueryRowContext(ctx, `SELECT client_secret_ref FROM oidc_providers WHERE id = ?`, oidcProviderID).Scan(&ref)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if secret == "" {
				return errors.New("a new sso provider needs a client secret")
			}
			if ref, err = s.secretBox.Put(ctx, tx, []byte(secret)); err != nil {
				return fmt.Errorf("seal client secret: %w", err)
			}
		case err != nil:
			return fmt.Errorf("read client secret reference: %w", err)
		case secret != "":
			if err := s.secretBox.Replace(ctx, tx, ref, []byte(secret)); err != nil {
				return fmt.Errorf("seal client secret: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_providers
			(id, issuer, client_id, client_secret_ref, scopes_json, groups_claim, allowed_domains_json, auto_provision, link_existing, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id,
				scopes_json = excluded.scopes_json, groups_claim = excluded.groups_claim,
				allowed_domains_json = excluded.allowed_domains_json, auto_provision = excluded.auto_provision,
				link_existing = excluded.link_existing, updated_at = excluded.updated_at`,
			oidcProviderID, p.Issuer, p.ClientID, ref, string(scopes), p.GroupsClaim, string(domains),
			boolInt(p.AutoProvision), boolInt(p.LinkExisting), p.UpdatedAt.UnixMilli()); err != nil {
			return fmt.Errorf("save sso settings: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// DeleteOIDCProvider removes the settings and their sealed secret, with the audit entry.
func (s *Store) DeleteOIDCProvider(ctx context.Context, ev audit.Event) error {
	if s.secretBox == nil {
		return errors.New("secrets are not configured")
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var ref string
		err := tx.QueryRowContext(ctx, `SELECT client_secret_ref FROM oidc_providers WHERE id = ?`, oidcProviderID).Scan(&ref)
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read client secret reference: %w", err)
		}
		// The row references the secret, so it goes first.
		if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_providers WHERE id = ?`, oidcProviderID); err != nil {
			return fmt.Errorf("delete sso settings: %w", err)
		}
		if err := s.secretBox.Delete(ctx, tx, ref); err != nil {
			return fmt.Errorf("delete client secret: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// CreateOIDCLogin stores a pending sign-in and drops expired ones.
func (s *Store) CreateOIDCLogin(ctx context.Context, l auth.OIDCLogin) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_logins WHERE expires_at < ?`, s.now().UnixMilli()); err != nil {
			return fmt.Errorf("drop expired sign-ins: %w", err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO oidc_logins (state_hash, nonce, code_verifier, redirect_to, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			l.StateHash, l.Nonce, l.CodeVerifier, l.RedirectTo, s.now().UnixMilli(), l.ExpiresAt.UnixMilli())
		if err != nil {
			return fmt.Errorf("insert sign-in: %w", err)
		}
		return nil
	})
}

// TakeOIDCLogin returns a pending sign-in and deletes it in the same transaction, so a second use fails.
func (s *Store) TakeOIDCLogin(ctx context.Context, stateHash string) (auth.OIDCLogin, error) {
	var l auth.OIDCLogin
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var expires int64
		err := tx.QueryRowContext(ctx, `SELECT nonce, code_verifier, redirect_to, expires_at FROM oidc_logins WHERE state_hash = ?`, stateHash).
			Scan(&l.Nonce, &l.CodeVerifier, &l.RedirectTo, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read sign-in: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_logins WHERE state_hash = ?`, stateHash); err != nil {
			return fmt.Errorf("delete sign-in: %w", err)
		}
		l.StateHash = stateHash
		l.ExpiresAt = time.UnixMilli(expires)
		return nil
	})
	return l, err
}

// UserByOIDCSubject finds the account linked to an identity.
func (s *Store) UserByOIDCSubject(ctx context.Context, issuer, subject string) (auth.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, name, COALESCE(password_hash, ''), disabled, created_at FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`,
		issuer, subject))
}

// SignInOIDC applies a verified sign-in: it creates or links the account as the mode says, replaces
// the account's groups with the ones reported now, and appends ev. Everything commits together.
func (s *Store) SignInOIDC(ctx context.Context, in auth.OIDCSignIn, ev audit.Event) (auth.User, error) {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		switch in.Mode {
		case auth.OIDCLinkAccount:
			res, err := tx.ExecContext(ctx, `UPDATE users SET oidc_issuer = ?, oidc_subject = ? WHERE id = ? AND oidc_subject IS NULL`,
				in.Issuer, in.Subject, in.User.ID)
			if err != nil {
				return fmt.Errorf("link identity: %w", err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return auth.ErrOIDCLinkConflict
			}
		case auth.OIDCNewAccount:
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE email = ?`, in.User.Email).Scan(&n); err != nil {
				return fmt.Errorf("check email: %w", err)
			}
			if n > 0 {
				return auth.ErrOIDCEmailTaken
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, email, name, password_hash, oidc_issuer, oidc_subject, disabled, created_at)
				VALUES (?, ?, ?, NULL, ?, ?, 0, ?)`,
				in.User.ID, in.User.Email, in.User.Name, in.Issuer, in.Subject, in.User.CreatedAt.UnixMilli()); err != nil {
				return fmt.Errorf("insert user: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_user_groups WHERE user_id = ?`, in.User.ID); err != nil {
			return fmt.Errorf("clear groups: %w", err)
		}
		for _, g := range in.Groups {
			if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_user_groups (user_id, group_name) VALUES (?, ?)`, in.User.ID, g); err != nil {
				return fmt.Errorf("insert group: %w", err)
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
	if err != nil {
		return auth.User{}, err
	}
	return s.userByID(ctx, in.User.ID)
}

// OIDCGroupsOf lists the groups from the user's latest sign-in. It is the Store.Groups hook.
func (s *Store) OIDCGroupsOf(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT group_name FROM oidc_user_groups WHERE user_id = ? ORDER BY group_name`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) userByID(ctx context.Context, id string) (auth.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, name, COALESCE(password_hash, ''), disabled, created_at FROM users WHERE id = ?`, id))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
