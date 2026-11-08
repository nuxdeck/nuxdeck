// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

const (
	defaultIdleTimeout     = 12 * time.Hour
	defaultAbsoluteTimeout = 7 * 24 * time.Hour
	touchInterval          = time.Minute
	maxFailuresPerWindow   = 10
	failureWindow          = 5 * time.Minute
	maxAccountFailures     = 5
	accountLockWindow      = 15 * time.Minute
	maxNameRunes           = 100
	maxEmailLen            = 254
	maxUserAgentLen        = 256
)

// FieldError ties a validation failure to the request field it concerns.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Err.Error() }

func (e *FieldError) Unwrap() error { return e.Err }

// Config wires a Service.
type Config struct {
	Repo       Repository
	Hasher     *Hasher
	Passwords  *PasswordPolicy
	SetupToken *SetupToken
	Log        *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// IdleTimeout (default 12 hours, ACC-6) and AbsoluteTimeout (default 7 days) bound a session.
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	// Accounts enables two-factor, API tokens and user management; nil means password-only sign-in.
	Accounts *Accounts
}

// Service implements first-run setup, sign-in, sign-out and session lookup.
type Service struct {
	cfg       Config
	limiter   *Limiter
	lockout   *Limiter // per account and address (ACC-7)
	tickets   *ticketStore
	dummyHash string
}

// SignedIn is the result of a successful setup or sign-in.
type SignedIn struct {
	// Cookie is the session cookie value; only its hash is stored.
	Cookie    string
	CSRFToken string
	ExpiresAt time.Time
	User      User
	Roles     []Role
	// Pending is set instead of a session when a second factor is still needed.
	Pending *PendingLogin
}

// SetupRequest creates the first administrator.
type SetupRequest struct {
	Token    string
	Name     string
	Email    string
	Password string
}

// NewService validates cfg and prepares the constant-time dummy hash.
func NewService(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.AbsoluteTimeout == 0 {
		cfg.AbsoluteTimeout = defaultAbsoluteTimeout
	}
	if cfg.Repo == nil || cfg.Hasher == nil || cfg.Passwords == nil || cfg.SetupToken == nil || cfg.Log == nil {
		return nil, errors.New("auth: Repo, Hasher, Passwords, SetupToken and Log are required")
	}
	filler, err := randomToken()
	if err != nil {
		return nil, err
	}
	dummy, err := cfg.Hasher.Hash(ctx, filler)
	if err != nil {
		return nil, fmt.Errorf("prepare dummy hash: %w", err)
	}
	return &Service{
		cfg: cfg, limiter: NewLimiter(maxFailuresPerWindow, failureWindow, cfg.Now), dummyHash: dummy,
		lockout: NewLimiter(maxAccountFailures, accountLockWindow, cfg.Now), tickets: newTicketStore(cfg.Now),
	}, nil
}

// SetupRequired reports whether no account exists yet.
func (s *Service) SetupRequired(ctx context.Context) (bool, error) {
	n, err := s.cfg.Repo.UserCount(ctx)
	if err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}
	return n == 0, nil
}

// CompleteSetup creates the first administrator, consumes the setup token and signs the new admin in.
func (s *Service) CompleteSetup(ctx context.Context, req SetupRequest, c Client) (*SignedIn, error) {
	if s.limiter.Blocked(c.IP) {
		return nil, errcode.New(errcode.AuthDeny002, "setup attempts from %s are rate limited", c.IP)
	}
	required, err := s.SetupRequired(ctx)
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, errcode.New(errcode.AuthSetup002, "an administrator already exists")
	}
	if !s.cfg.SetupToken.Verify(req.Token) {
		s.recordFailure(ctx, c, "setup.failed", "bad_setup_token", "")
		return nil, errcode.New(errcode.AuthSetup001, "setup token does not match")
	}

	email, err := normalizeEmail(req.Email)
	if err != nil {
		return nil, &FieldError{Field: "email", Err: err}
	}
	name, err := normalizeName(req.Name)
	if err != nil {
		return nil, &FieldError{Field: "name", Err: err}
	}
	if err := s.cfg.Passwords.Check(req.Password, email); err != nil {
		return nil, &FieldError{Field: "password", Err: err}
	}
	hash, err := s.cfg.Hasher.Hash(ctx, req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	id, err := ids.New()
	if err != nil {
		return nil, err
	}

	now := s.cfg.Now()
	user := User{ID: id, Email: email, Name: name, PasswordHash: hash, CreatedAt: now}
	err = s.cfg.Repo.CreateAdmin(ctx, user, audit.Event{
		ActorType: "user", ActorID: user.ID, Action: "setup.admin_created", TargetType: "user", TargetID: user.ID,
		IP: c.IP, Result: audit.ResultSuccess,
	})
	if errors.Is(err, ErrSetupDone) {
		return nil, errcode.New(errcode.AuthSetup002, "an administrator already exists")
	}
	if err != nil {
		return nil, fmt.Errorf("create administrator: %w", err)
	}
	if err := s.cfg.SetupToken.Remove(); err != nil {
		s.cfg.Log.Warn("could not remove the setup token file", "error", err)
	}
	return s.startSession(ctx, user, c, "setup")
}

// Login checks the credentials and starts a session. Unknown accounts, wrong
// passwords and disabled accounts are indistinguishable to the caller, in
// message and in timing.
func (s *Service) Login(ctx context.Context, email, password string, c Client) (*SignedIn, error) {
	if s.limiter.Blocked(c.IP) {
		return nil, errcode.New(errcode.AuthDeny002, "sign-in attempts from %s are rate limited", c.IP)
	}
	normalized, emailErr := normalizeEmail(email)
	lockKey := normalized + "|" + c.IP
	if emailErr == nil && s.lockout.Blocked(lockKey) {
		return nil, errcode.New(errcode.AuthLock001, "account locked for this address")
	}
	if emailErr != nil || len(password) > maxPasswordBytes {
		s.recordFailure(ctx, c, "auth.login_failed", "malformed_credentials", normalized)
		return nil, errcode.New(errcode.AuthDeny001, "credentials rejected")
	}

	user, err := s.cfg.Repo.UserByEmail(ctx, normalized)
	known := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("look up user: %w", err)
	}
	hash := s.dummyHash
	if known {
		hash = user.PasswordHash
	}
	match, verr := s.cfg.Hasher.Verify(ctx, password, hash)
	if verr != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if verr != nil {
		s.cfg.Log.Error("password hash could not be verified", "user_id", user.ID, "error", verr)
	}

	switch {
	case !known:
		s.recordFailure(ctx, c, "auth.login_failed", "unknown_user", normalized)
	case user.Disabled:
		s.recordFailure(ctx, c, "auth.login_failed", "disabled_user", normalized)
	case !match:
		s.recordFailure(ctx, c, "auth.login_failed", "bad_password", normalized)
	default:
		return s.pendingLogin(ctx, user, c)
	}
	return nil, errcode.New(errcode.AuthDeny001, "credentials rejected")
}

// Authenticate resolves a session cookie. An absent, unknown or expired cookie
// yields the anonymous principal and no error; only storage failures are errors.
func (s *Service) Authenticate(ctx context.Context, cookie string) (Principal, *Session, error) {
	if cookie == "" {
		return Principal{}, nil, nil
	}
	hash := hashToken(cookie)
	sess, user, err := s.cfg.Repo.SessionByHash(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return Principal{}, nil, nil
	}
	if err != nil {
		return Principal{}, nil, fmt.Errorf("look up session: %w", err)
	}

	now := s.cfg.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.cfg.IdleTimeout || user.Disabled {
		if err := s.cfg.Repo.DeleteSession(ctx, hash, audit.Event{
			ActorType: "system", Action: "auth.session_expired", TargetType: "session", TargetID: hash[:12], Result: audit.ResultSuccess,
			Details: map[string]any{"user_id": user.ID},
		}); err != nil {
			s.cfg.Log.Warn("could not remove an expired session", "error", err)
		}
		return Principal{}, nil, nil
	}
	if now.Sub(sess.LastSeenAt) > touchInterval {
		if err := s.cfg.Repo.TouchSession(ctx, hash, now); err != nil {
			s.cfg.Log.Warn("could not refresh session activity", "error", err)
		} else {
			sess.LastSeenAt = now
		}
	}
	bindings, err := s.cfg.Repo.Bindings(ctx, user.ID)
	if err != nil {
		return Principal{}, nil, fmt.Errorf("look up role bindings: %w", err)
	}
	return Principal{UserID: user.ID, Email: user.Email, Name: user.Name, Roles: UnscopedRoles(bindings), Bindings: bindings, Via: "session"}, &sess, nil
}

// Logout ends the session.
func (s *Service) Logout(ctx context.Context, sess Session, c Client) error {
	return s.cfg.Repo.DeleteSession(ctx, sess.IDHash, audit.Event{
		ActorType: "user", ActorID: sess.UserID, Action: "auth.logout", TargetType: "session", TargetID: sess.IDHash[:12],
		IP: c.IP, Result: audit.ResultSuccess,
	})
}

// CheckCSRF compares the token a client sent with the session's token in constant time.
func (s *Service) CheckCSRF(sess Session, token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(sess.CSRFToken), []byte(token)) == 1
}

func (s *Service) startSession(ctx context.Context, user User, c Client, method string) (*SignedIn, error) {
	cookie, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	sess := Session{
		IDHash: hashToken(cookie), UserID: user.ID, CSRFToken: csrf, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(s.cfg.AbsoluteTimeout), IP: c.IP, UserAgent: truncate(c.UserAgent, maxUserAgentLen),
	}
	if err := s.cfg.Repo.CreateSession(ctx, sess, audit.Event{
		ActorType: "user", ActorID: user.ID, Action: "auth.login", TargetType: "session", TargetID: sess.IDHash[:12],
		IP: c.IP, Result: audit.ResultSuccess, Details: map[string]any{"method": method},
	}); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	bindings, err := s.cfg.Repo.Bindings(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("look up role bindings: %w", err)
	}
	return &SignedIn{Cookie: cookie, CSRFToken: csrf, ExpiresAt: sess.ExpiresAt, User: user, Roles: UnscopedRoles(bindings)}, nil
}

// recordFailure counts the failure against the caller's address and writes an
// audit entry. A failure to audit is logged, not returned: the caller must still be refused.
func (s *Service) recordFailure(ctx context.Context, c Client, action, reason, email string) {
	s.limiter.Fail(c.IP)
	if email != "" {
		key := email + "|" + c.IP
		s.lockout.Fail(key)
		if s.lockout.Blocked(key) {
			defer s.auditFail(ctx, "", c, "auth.locked", "login_failures")
		}
	}
	details := map[string]any{"reason": reason}
	if email != "" {
		details["email"] = maskEmail(email)
	}
	if err := s.cfg.Repo.RecordAudit(ctx, audit.Event{
		ActorType: "anonymous", Action: action, IP: c.IP, Result: audit.ResultFailure, Details: details,
	}); err != nil {
		s.cfg.Log.Error("could not write audit entry", "action", action, "error", err)
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxEmailLen {
		return s, errors.New("enter a valid email address")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return s, errors.New("enter a valid email address")
	}
	return strings.ToLower(s), nil
}

func normalizeName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > maxNameRunes {
		return "", fmt.Errorf("enter a name of 1 to %d characters", maxNameRunes)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errors.New("the name contains control characters")
		}
	}
	return s, nil
}

func maskEmail(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return "***"
	}
	r, _ := utf8.DecodeRuneInString(local)
	return string(r) + "***@" + domain
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
