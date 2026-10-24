// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

// Defaults from docs/03-architecture.md: tokens live 1 hour, certificates 24 hours renewed after 16.
const (
	DefaultTokenTTL = time.Hour
	MaxTokenTTL     = 24 * time.Hour
	CertTTL         = 24 * time.Hour
	RenewAfter      = 16 * time.Hour

	maxLabels      = 20
	maxLabelLength = 64
	maxFieldLength = 253
)

// ErrTokenInvalid is returned by a Repository when a token is unknown, expired or already used.
var ErrTokenInvalid = errors.New("enrolment token unknown, expired or used")

// TokenRecord is a stored token. The secret itself is never persisted.
type TokenRecord struct {
	ID         string
	Hash       string
	CreatedBy  string
	LabelsJSON string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// AgentRecord is the agent created when a token is redeemed.
type AgentRecord struct {
	ID         string
	CertSerial string
	Hostname   string
	OS         string
	Arch       string
	Version    string
	EnrolledAt time.Time
}

// Redemption is what a Repository's callback returns for a valid token.
type Redemption struct {
	Agent AgentRecord
	Event audit.Event
}

// Repository is the persistence the pki module needs.
type Repository interface {
	// CreateEnrollmentToken stores t and appends ev in one transaction.
	CreateEnrollmentToken(ctx context.Context, t TokenRecord, ev audit.Event) error
	// RedeemEnrollmentToken marks the token used if it is valid at now, calls redeem with its ID
	// and labels, then stores the agent and appends the audit event, all in one transaction.
	// If redeem fails nothing is kept and the token stays unused. It returns ErrTokenInvalid
	// for an unknown, expired or used token.
	RedeemEnrollmentToken(ctx context.Context, hash string, now time.Time, redeem func(tokenID, labelsJSON string) (Redemption, error)) error
	// RecordAudit appends an event that changes nothing else.
	RecordAudit(ctx context.Context, ev audit.Event) error
}

// Service creates enrolment tokens and signs agent certificates.
type Service struct {
	repo Repository
	ca   *CA
	// Now supplies the clock; nil means time.Now. Tests set it.
	Now func() time.Time
}

// NewService wires the module.
func NewService(repo Repository, ca *CA) *Service { return &Service{repo: repo, ca: ca} }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Actor identifies who asked, for the audit entry.
type Actor struct {
	UserID string
	IP     string
}

// TokenRequest asks for a new enrolment token.
type TokenRequest struct {
	ServerURL string
	// TTL defaults to DefaultTokenTTL and may not exceed MaxTokenTTL.
	TTL time.Duration
	// Labels become host tags on the enrolled agent.
	Labels map[string]string
}

// CreatedToken is shown to the admin once.
type CreatedToken struct {
	ID        string
	Token     string
	ExpiresAt time.Time
}

// CreateToken mints a single-use token and records it in the audit log.
func (s *Service) CreateToken(ctx context.Context, actor Actor, req TokenRequest) (CreatedToken, error) {
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	if ttl < 0 || ttl > MaxTokenTTL {
		return CreatedToken{}, &FieldError{Field: "ttl_seconds", Msg: fmt.Sprintf("must be between 1 and %d seconds", int(MaxTokenTTL.Seconds()))}
	}
	if err := validateLabels(req.Labels); err != nil {
		return CreatedToken{}, err
	}
	labels, err := json.Marshal(nonNil(req.Labels))
	if err != nil {
		return CreatedToken{}, fmt.Errorf("encode labels: %w", err)
	}
	tok, err := NewToken(req.ServerURL, s.ca.Fingerprint())
	if err != nil {
		return CreatedToken{}, err
	}
	// The URL is validated by the shape check a redeemer would apply.
	if _, err := ParseToken(tok.String()); err != nil {
		return CreatedToken{}, &FieldError{Field: "server_url", Msg: "must be an https URL"}
	}
	id, err := ids.New()
	if err != nil {
		return CreatedToken{}, err
	}
	now := s.now()
	rec := TokenRecord{ID: id, Hash: tok.Hash(), CreatedBy: actor.UserID, LabelsJSON: string(labels), CreatedAt: now, ExpiresAt: now.Add(ttl)}
	ev := audit.Event{
		ActorType: "user", ActorID: actor.UserID, Action: "agent.token.create",
		TargetType: "enrollment_token", TargetID: id, IP: actor.IP, Result: audit.ResultSuccess,
		Details: map[string]any{"expires_at": rec.ExpiresAt.UnixMilli(), "labels": nonNil(req.Labels)},
	}
	if err := s.repo.CreateEnrollmentToken(ctx, rec, ev); err != nil {
		return CreatedToken{}, fmt.Errorf("store enrolment token: %w", err)
	}
	return CreatedToken{ID: id, Token: tok.String(), ExpiresAt: rec.ExpiresAt}, nil
}

// EnrollRequest is what an agent sends over the not-yet-mutual TLS connection.
type EnrollRequest struct {
	Token    string
	CSRDER   []byte
	Version  string
	Hostname string
	OS       string
	Arch     string
	IP       string
}

// Enrollment is the agent's first identity.
type Enrollment struct {
	AgentID    string
	CertDER    []byte
	CACertDER  []byte
	RenewAfter time.Time
}

// Enroll redeems a token and signs the agent's request. The certificate is issued
// inside the redemption transaction, so a token is spent exactly when a certificate exists.
func (s *Service) Enroll(ctx context.Context, req EnrollRequest) (*Enrollment, error) {
	tok, err := ParseToken(req.Token)
	if err != nil {
		s.auditRejected(ctx, req, "malformed")
		return nil, err
	}
	// A bad request must not burn a valid token, so check it before redeeming.
	if _, err := checkCSR(req.CSRDER); err != nil {
		s.auditRejected(ctx, req, "bad_csr")
		return nil, err
	}
	for _, f := range []struct{ name, val string }{{"version", req.Version}, {"hostname", req.Hostname}, {"os", req.OS}, {"arch", req.Arch}} {
		if len(f.val) > maxFieldLength {
			return nil, errcode.New(errcode.GWCSR001, "%s is too long", f.name)
		}
	}

	now := s.now()
	var out *Enrollment
	err = s.repo.RedeemEnrollmentToken(ctx, tok.Hash(), now, func(tokenID, _ string) (Redemption, error) {
		agentID, err := ids.New()
		if err != nil {
			return Redemption{}, err
		}
		issued, err := s.ca.Sign(req.CSRDER, agentID, now, CertTTL)
		if err != nil {
			return Redemption{}, err
		}
		out = &Enrollment{AgentID: agentID, CertDER: issued.DER, CACertDER: s.ca.CertDER(), RenewAfter: now.Add(RenewAfter)}
		return Redemption{
			Agent: AgentRecord{ID: agentID, CertSerial: issued.Serial, Hostname: req.Hostname, OS: req.OS, Arch: req.Arch, Version: req.Version, EnrolledAt: now},
			Event: audit.Event{
				ActorType: "agent", ActorID: agentID, Action: "agent.enroll",
				TargetType: "agent", TargetID: agentID, IP: req.IP, Result: audit.ResultSuccess,
				Details: map[string]any{"token_id": tokenID, "cert_serial": issued.Serial, "hostname": req.Hostname},
			},
		}, nil
	})
	switch {
	case errors.Is(err, ErrTokenInvalid):
		s.auditRejected(ctx, req, "invalid_token")
		return nil, errcode.New(errcode.GWTok001, "token unknown, expired or used")
	case err != nil:
		return nil, fmt.Errorf("enrol agent: %w", err)
	}
	return out, nil
}

// auditRejected records a failed attempt. It is best effort: the caller already has an error to return.
func (s *Service) auditRejected(ctx context.Context, req EnrollRequest, reason string) {
	_ = s.repo.RecordAudit(ctx, audit.Event{
		ActorType: "anonymous", ActorID: "", Action: "agent.enroll",
		TargetType: "agent", TargetID: "", IP: req.IP, Result: audit.ResultFailure,
		Details: map[string]any{"reason": reason},
	})
}

// FieldError names the request field that failed validation.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func validateLabels(labels map[string]string) error {
	if len(labels) > maxLabels {
		return &FieldError{Field: "labels", Msg: fmt.Sprintf("at most %d labels", maxLabels)}
	}
	for k, v := range labels {
		if k == "" || len(k) > maxLabelLength || len(v) > maxLabelLength {
			return &FieldError{Field: "labels", Msg: fmt.Sprintf("keys must be 1 to %d characters and values at most %d", maxLabelLength, maxLabelLength)}
		}
	}
	return nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
