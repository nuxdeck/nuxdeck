// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

const (
	ticketTTL         = 5 * time.Minute
	ticketMaxAttempts = 5
	maxTickets        = 10_000
)

// PendingLogin is returned instead of a session when the password was right but a second factor is still needed.
type PendingLogin struct {
	Ticket    string
	ExpiresAt time.Time
	// EnrolRequired means the user has no authenticator yet and the server requires one.
	EnrolRequired bool
}

type ticket struct {
	userID   string
	ip       string
	expires  time.Time
	enrol    bool
	attempts int
}

// ticketStore holds pending logins in memory only: a restart makes users sign in again.
type ticketStore struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*ticket
}

func newTicketStore(now func() time.Time) *ticketStore {
	return &ticketStore{now: now, m: map[string]*ticket{}}
}

func (t *ticketStore) issue(userID, ip string, enrol bool) (PendingLogin, error) {
	raw, err := randomToken()
	if err != nil {
		return PendingLogin{}, err
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= maxTickets {
		for k, v := range t.m {
			if now.After(v.expires) {
				delete(t.m, k)
			}
		}
		if len(t.m) >= maxTickets {
			t.m = map[string]*ticket{}
		}
	}
	exp := now.Add(ticketTTL)
	t.m[hashToken(raw)] = &ticket{userID: userID, ip: ip, expires: exp, enrol: enrol}
	return PendingLogin{Ticket: raw, ExpiresAt: exp, EnrolRequired: enrol}, nil
}

// lookup returns a copy of the live ticket for raw, bound to the address that signed in.
func (t *ticketStore) lookup(raw, ip string) (ticket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := hashToken(raw)
	e, ok := t.m[k]
	if !ok {
		return ticket{}, false
	}
	if t.now().After(e.expires) || e.ip != ip {
		delete(t.m, k)
		return ticket{}, false
	}
	return *e, true
}

// miss counts a wrong code and burns the ticket after too many.
func (t *ticketStore) miss(raw string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := hashToken(raw)
	if e, ok := t.m[k]; ok {
		e.attempts++
		if e.attempts >= ticketMaxAttempts {
			delete(t.m, k)
		}
	}
}

func (t *ticketStore) consume(raw string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, hashToken(raw))
}

// BeginTOTPEnrolment creates an unconfirmed secret for the user.
func (a *Accounts) BeginTOTPEnrolment(ctx context.Context, p Principal, c Client) (TOTPEnrolment, error) {
	acc, err := a.GetUser(ctx, p.UserID)
	if err != nil {
		return TOTPEnrolment{}, err
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return TOTPEnrolment{}, err
	}
	err = a.repo.BeginTOTP(ctx, acc.ID, secret, actor(p, "totp.enrol_started", "user", acc.ID, c, nil))
	if errors.Is(err, ErrBadState) {
		return TOTPEnrolment{}, errcode.New(errcode.AuthTOTP003, "two-factor is already on")
	}
	if err != nil {
		return TOTPEnrolment{}, fmt.Errorf("start enrolment: %w", err)
	}
	return TOTPEnrolment{Secret: EncodeTOTPSecret(secret), URI: OTPAuthURI(a.issuer, acc.Email, secret)}, nil
}

// ConfirmTOTP checks the first code, turns two-factor on and returns the one-time recovery codes.
func (a *Accounts) ConfirmTOTP(ctx context.Context, p Principal, code string, c Client) ([]string, error) {
	return a.confirm(ctx, p, p.UserID, code, c)
}

func (a *Accounts) confirm(ctx context.Context, p Principal, userID, code string, c Client) ([]string, error) {
	key := "totp:" + userID
	if a.guard.Blocked(key) {
		return nil, errcode.New(errcode.AuthLock001, "too many failed attempts")
	}
	st, err := a.repo.TOTPState(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("look up two-factor state: %w", err)
	}
	if !st.Pending || st.Enabled {
		return nil, errcode.New(errcode.AuthTOTP003, "no enrolment in progress")
	}
	secret, err := a.repo.TOTPSecret(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	step, ok := VerifyTOTP(secret, code, a.now(), st.LastStep)
	if !ok {
		a.guard.Fail(key)
		a.auditFailure(ctx, p, c, "totp.confirm_failed", "bad_code")
		return nil, errcode.New(errcode.AuthTOTP001, "code rejected")
	}
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := a.repo.ConfirmTOTP(ctx, userID, step, hashes, actor(p, "totp.enabled", "user", userID, c, nil)); err != nil {
		if errors.Is(err, ErrBadState) {
			return nil, errcode.New(errcode.AuthTOTP003, "no enrolment in progress")
		}
		return nil, fmt.Errorf("enable two-factor: %w", err)
	}
	return codes, nil
}

// DisableTOTP turns two-factor off after re-checking the password. It is refused while the server requires it.
func (a *Accounts) DisableTOTP(ctx context.Context, p Principal, password string, c Client) error {
	acc, err := a.GetUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if err := a.verifyOwnPassword(ctx, acc, password, c); err != nil {
		return err
	}
	required, err := a.repo.Require2FA(ctx)
	if err != nil {
		return err
	}
	if required {
		return errcode.New(errcode.AuthTOTP003, "the administrator requires two-factor")
	}
	err = a.repo.DisableTOTP(ctx, p.UserID, actor(p, "totp.disabled", "user", p.UserID, c, nil))
	if errors.Is(err, ErrBadState) {
		return errcode.New(errcode.AuthTOTP003, "two-factor is not on")
	}
	return err
}

// TOTPStatus reports the user's state and how many recovery codes remain.
func (a *Accounts) TOTPStatus(ctx context.Context, userID string) (enabled bool, recovery int, err error) {
	st, err := a.repo.TOTPState(ctx, userID)
	if err != nil {
		return false, 0, err
	}
	if !st.Enabled {
		return false, 0, nil
	}
	n, err := a.repo.RecoveryCodeCount(ctx, userID)
	return true, n, err
}

// secondFactor accepts a current TOTP code (once only) or an unused recovery code.
func (a *Accounts) secondFactor(ctx context.Context, userID, code string, c Client) (bool, error) {
	st, err := a.repo.TOTPState(ctx, userID)
	if err != nil {
		return false, err
	}
	if !st.Enabled {
		return false, nil
	}
	secret, err := a.repo.TOTPSecret(ctx, userID)
	if err != nil {
		return false, err
	}
	if step, ok := VerifyTOTP(secret, code, a.now(), st.LastStep); ok {
		return a.repo.AdvanceTOTPStep(ctx, userID, step)
	}
	h := hashRecoveryCode(code)
	if h == "" {
		return false, nil
	}
	return a.repo.UseRecoveryCode(ctx, userID, h, audit.Event{
		ActorType: "user", ActorID: userID, Action: "totp.recovery_code_used", TargetType: "user", TargetID: userID,
		IP: c.IP, Result: audit.ResultSuccess,
	})
}

// pendingLogin decides whether a correct password still needs a second factor.
func (s *Service) pendingLogin(ctx context.Context, user User, c Client) (*SignedIn, error) {
	acc := s.cfg.Accounts
	if acc == nil {
		return s.startSession(ctx, user, c, "password")
	}
	st, err := acc.repo.TOTPState(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("look up two-factor state: %w", err)
	}
	required, err := acc.repo.Require2FA(ctx)
	if err != nil {
		return nil, fmt.Errorf("look up two-factor setting: %w", err)
	}
	if !st.Enabled && !required {
		return s.startSession(ctx, user, c, "password")
	}
	pl, err := s.tickets.issue(user.ID, c.IP, !st.Enabled)
	if err != nil {
		return nil, err
	}
	return &SignedIn{User: user, Pending: &pl}, nil
}

func (s *Service) liveTicket(raw string, c Client) (ticket, error) {
	t, ok := s.tickets.lookup(raw, c.IP)
	if !ok {
		return ticket{}, errcode.New(errcode.AuthTOTP002, "sign-in step expired")
	}
	return t, nil
}

// BeginPendingEnrolment starts TOTP enrolment for a user who must have it but does not yet.
func (s *Service) BeginPendingEnrolment(ctx context.Context, rawTicket string, c Client) (TOTPEnrolment, error) {
	acc := s.cfg.Accounts
	t, err := s.liveTicket(rawTicket, c)
	if err != nil {
		return TOTPEnrolment{}, err
	}
	if acc == nil || !t.enrol {
		return TOTPEnrolment{}, errcode.New(errcode.AuthTOTP003, "enrolment not needed")
	}
	return acc.BeginTOTPEnrolment(ctx, Principal{UserID: t.userID}, c)
}

// VerifyTOTP completes a pending login with a TOTP or recovery code, or finishes a
// required enrolment. recovery holds the new recovery codes after an enrolment.
func (s *Service) VerifyTOTP(ctx context.Context, rawTicket, code string, c Client) (in *SignedIn, recovery []string, err error) {
	acc := s.cfg.Accounts
	t, err := s.liveTicket(rawTicket, c)
	if err != nil {
		return nil, nil, err
	}
	if acc == nil {
		return nil, nil, errcode.New(errcode.AuthTOTP002, "two-factor is not configured")
	}
	key := "totp:" + t.userID + "|" + c.IP
	if s.limiter.Blocked(c.IP) || s.lockout.Blocked(key) {
		return nil, nil, errcode.New(errcode.AuthLock001, "too many failed attempts")
	}
	user, err := acc.repo.AccountByID(ctx, t.userID)
	if err != nil || user.Disabled {
		s.tickets.consume(rawTicket)
		return nil, nil, errcode.New(errcode.AuthTOTP002, "sign-in step expired")
	}

	p := Principal{UserID: user.ID}
	ok := false
	if t.enrol {
		recovery, err = acc.confirm(ctx, p, user.ID, code, c)
		switch {
		case err == nil:
			ok = true
		case errcode.CodeOf(err) != errcode.AuthTOTP001:
			return nil, nil, err
		}
	} else {
		ok, err = acc.secondFactor(ctx, user.ID, code, c)
		if err != nil {
			return nil, nil, fmt.Errorf("check second factor: %w", err)
		}
	}
	if !ok {
		s.tickets.miss(rawTicket)
		s.lockout.Fail(key)
		s.limiter.Fail(c.IP)
		s.auditFail(ctx, user.ID, c, "auth.totp_failed", "bad_code")
		if s.lockout.Blocked(key) {
			s.auditFail(ctx, user.ID, c, "auth.locked", "totp_failures")
		}
		return nil, nil, errcode.New(errcode.AuthTOTP001, "code rejected")
	}
	s.tickets.consume(rawTicket)
	in, err = s.startSession(ctx, user.User, c, "password+totp")
	return in, recovery, err
}

func (s *Service) auditFail(ctx context.Context, userID string, c Client, action, reason string) {
	if err := s.cfg.Repo.RecordAudit(ctx, audit.Event{
		ActorType: "user", ActorID: userID, Action: action, IP: c.IP, Result: audit.ResultFailure, Details: map[string]any{"reason": reason},
	}); err != nil {
		s.cfg.Log.Error("could not write audit entry", "action", action, "error", err)
	}
}
