// SPDX-License-Identifier: AGPL-3.0-only

// Package alerting evaluates alert rules over check results, host liveness, container state
// and metrics (ALR-1, ALR-2), keeps exactly one open alert per rule and item, routes
// notifications to channels (ALR-4), and lets operators acknowledge alerts, silence them and
// schedule maintenance windows (ALR-5). Delivery lives in the notify subpackage.
package alerting

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

// Rule kinds (ALR-1).
const (
	KindCheckDown        = "check_down"
	KindHostOffline      = "host_offline"
	KindContainerStopped = "container_stopped"
	KindMetricThreshold  = "metric_threshold"
	KindTLSExpiring      = "tls_expiring"
)

// Severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Alert states. An alert is open or acked while its condition holds, then resolved.
const (
	StateOpen     = "open"
	StateAcked    = "acked"
	StateResolved = "resolved"
)

// Item types.
const (
	ItemHost      = "host"
	ItemContainer = "container"
	ItemCheck     = "check"
)

// Silence kinds. Both mute notifications; a maintenance window is the scheduled kind.
const (
	SilenceKindSilence     = "silence"
	SilenceKindMaintenance = "maintenance"
)

// Limits.
const (
	MaxRules          = 1000
	MaxRoutes         = 100
	MaxSelectorItems  = 50
	MaxSilenceLength  = 30 * 24 * time.Hour
	MaxMaintenance    = 90 * 24 * time.Hour
	MaxScheduleAhead  = 365 * 24 * time.Hour
	MaxReasonLength   = 200
	MaxNameLength     = 100
	MaxActiveAlerts   = 10000
	FlapWindow        = 30 * time.Minute
	AlertRetention    = 90 * 24 * time.Hour
	SilenceRetention  = 30 * 24 * time.Hour
	DefaultEvalPeriod = 15 * time.Second
)

// Errors returned by Service methods.
var (
	ErrNotFound    = errors.New("not found")
	ErrStale       = errors.New("changed since it was read")
	ErrResolved    = errors.New("alert is resolved")
	ErrRateLimited = errors.New("requested too often")
)

// ValidationError names the offending field of a request.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, msg string) error { return &ValidationError{field, msg} }

// Actor identifies who changes something, for the audit entry.
type Actor struct{ UserID, IP string }

// Selector narrows what a rule, route or silence applies to. Every non-empty field must match.
// Tags are `key` or `key:value` and all must be present; IDs, Severity and Kinds match any
// listed value. A rule's selector may use Tags and IDs only; a check has no tags, so a tag
// selector never matches a check.
type Selector struct {
	Tags     []string `json:"tags"`
	IDs      []string `json:"ids"`
	Severity []string `json:"severity"`
	Kinds    []string `json:"kinds"`
}

// subject is what a selector is matched against.
type subject struct {
	id       string
	tags     map[string]string
	severity string
	kind     string
}

var ulidPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// empty reports whether the selector matches everything.
func (s Selector) empty() bool {
	return len(s.Tags) == 0 && len(s.IDs) == 0 && len(s.Severity) == 0 && len(s.Kinds) == 0
}

func (s Selector) matches(sub subject) bool {
	if len(s.IDs) > 0 && !contains(s.IDs, sub.id) {
		return false
	}
	if len(s.Severity) > 0 && !contains(s.Severity, sub.severity) {
		return false
	}
	if len(s.Kinds) > 0 && !contains(s.Kinds, sub.kind) {
		return false
	}
	for _, t := range s.Tags {
		sel, err := inventory.ParseSelector(t)
		if err != nil {
			return false
		}
		v, ok := sub.tags[sel.Key]
		if !ok || (sel.Value != "" && v != sel.Value) {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// normalize returns the selector with nil lists replaced by empty ones, so JSON shows [].
func (s Selector) normalize() Selector {
	nz := func(l []string) []string {
		if l == nil {
			return []string{}
		}
		return l
	}
	return Selector{Tags: nz(s.Tags), IDs: nz(s.IDs), Severity: nz(s.Severity), Kinds: nz(s.Kinds)}
}

// validate checks the selector. allowed names the fields the context permits.
func (s Selector) validate(field string, tags, idsOK, severity, kinds bool) error {
	for name, l := range map[string][]string{"tags": s.Tags, "ids": s.IDs, "severity": s.Severity, "kinds": s.Kinds} {
		if len(l) > MaxSelectorItems {
			return bad(field+"."+name, "Use at most 50 entries.")
		}
	}
	if (len(s.Tags) > 0 && !tags) || (len(s.IDs) > 0 && !idsOK) || (len(s.Severity) > 0 && !severity) || (len(s.Kinds) > 0 && !kinds) {
		return bad(field, "This selector field is not allowed here.")
	}
	for _, t := range s.Tags {
		if _, err := inventory.ParseSelector(t); err != nil {
			return bad(field+".tags", "Use key:value, for example env:production.")
		}
	}
	for _, id := range s.IDs {
		if !ulidPattern.MatchString(id) {
			return bad(field+".ids", "Use item IDs.")
		}
	}
	for _, v := range s.Severity {
		if !validSeverity(v) {
			return bad(field+".severity", "Use info, warning or critical.")
		}
	}
	for _, k := range s.Kinds {
		if !validKind(k) {
			return bad(field+".kinds", "Use a rule kind such as check_down.")
		}
	}
	return nil
}

func validSeverity(v string) bool {
	return v == SeverityInfo || v == SeverityWarning || v == SeverityCritical
}

func validKind(k string) bool {
	switch k {
	case KindCheckDown, KindHostOffline, KindContainerStopped, KindMetricThreshold, KindTLSExpiring:
		return true
	}
	return false
}

// Rule is an alert rule as the API reads and writes it.
type Rule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	Enabled   bool            `json:"enabled"`
	Selector  Selector        `json:"selector"`
	Params    json.RawMessage `json:"params"`
	CreatedBy string          `json:"created_by"`
	UpdatedBy string          `json:"updated_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Rev       int64           `json:"-"`
}

// ETag identifies the stored version of a rule.
func (r Rule) ETag() string { return `"a` + itoa(r.Rev) + `"` }

// Alert is one alert as the API reads it.
type Alert struct {
	ID             string     `json:"id"`
	RuleID         string     `json:"rule_id"`
	RuleName       string     `json:"rule_name"`
	Kind           string     `json:"kind"`
	Severity       string     `json:"severity"`
	ItemType       string     `json:"item_type"`
	ItemID         string     `json:"item_id"`
	ItemName       string     `json:"item_name"`
	Summary        string     `json:"summary"`
	Link           string     `json:"link"`
	State          string     `json:"state"`
	OpenedAt       time.Time  `json:"opened_at"`
	AckedBy        string     `json:"acked_by"`
	AckedAt        *time.Time `json:"acked_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	ResolveReason  string     `json:"resolve_reason"`
	FlapCount      int        `json:"flap_count"`
	LastNotifiedAt *time.Time `json:"last_notified_at"`

	fingerprint   string
	notifyPending bool
}

// Silence is a silence or maintenance window.
type Silence struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Selector  Selector  `json:"selector"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// State is scheduled, active or expired; the server fills it on output.
	State string `json:"state"`
}

// Route sends matching alerts to one channel. With Continue, later routes are tried too;
// without it the first match wins.
type Route struct {
	ID        string   `json:"id,omitempty"`
	Selector  Selector `json:"selector"`
	ChannelID string   `json:"channel_id"`
	Continue  bool     `json:"continue"`
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for ; n > 0; n /= 10 {
		i--
		b[i] = byte('0' + n%10)
	}
	return string(b[i:])
}

func clean(s string) string { return strings.TrimSpace(s) }
