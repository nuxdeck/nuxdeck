// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits keep every document, and so every public response, small and bounded.
const (
	MaxPages            = 100
	MaxComponents       = 20
	MaxChecksPerComp    = 50
	MaxTitle            = 100
	MaxDescription      = 500
	MaxComponentName    = 80
	MaxIncidentTitle    = 140
	MaxIncidentBody     = 2000
	MaxIncidentsPerPage = 500
	MaxUpdatesPerInc    = 100
)

// Incident statuses and impacts.
const (
	IncInvestigating = "investigating"
	IncIdentified    = "identified"
	IncMonitoring    = "monitoring"
	IncResolved      = "resolved"

	ImpactNone  = "none"
	ImpactMinor = "minor"
	ImpactMajor = "major"
)

// Errors returned by Service methods.
var (
	ErrNotFound  = errors.New("status page not found")
	ErrStale     = errors.New("status page changed since it was read")
	ErrSlugTaken = errors.New("slug already in use")
)

// ValidationError names the offending field and carries a hint safe to show the user.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, msg string) error { return &ValidationError{field, msg} }

// SlugPattern is the only shape of slug that is stored or looked up.
var SlugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// reservedSlugs would shadow static paths under /status/.
var reservedSlugs = map[string]bool{"assets": true}

var checkID = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// ComponentInput is a component as the API receives it. ID is accepted so a fetched page
// can be edited and sent back; it is ignored.
type ComponentInput struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	CheckIDs []string `json:"check_ids"`
}

// PageInput is the editable part of a page. Slug is required on create and immutable after.
type PageInput struct {
	Slug        string           `json:"slug"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Published   bool             `json:"published"`
	Components  []ComponentInput `json:"components"`
}

// Component is a stored component.
type Component struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	CheckIDs []string `json:"check_ids"`
}

// Page is a status page as the admin API shows it.
type Page struct {
	ID          string      `json:"id"`
	Slug        string      `json:"slug"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Published   bool        `json:"published"`
	Components  []Component `json:"components"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	// Rev is the version behind the ETag.
	Rev int64 `json:"-"`
}

// ETag identifies the stored version of a page.
func (p Page) ETag() string { return `"p` + strconv.FormatInt(p.Rev, 10) + `"` }

// IncidentInput creates an incident.
type IncidentInput struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	Status string `json:"status"`
	Impact string `json:"impact"`
}

// UpdateInput adds a timeline entry. Impact, when set, replaces the incident's impact.
type UpdateInput struct {
	Status string `json:"status"`
	Body   string `json:"body"`
	Impact string `json:"impact,omitempty"`
}

// IncidentUpdate is one timeline entry.
type IncidentUpdate struct {
	Status    string    `json:"status"`
	Body      string    `json:"body"`
	CreatedBy string    `json:"created_by"`
	At        time.Time `json:"at"`
}

// Incident is an incident with its timeline, oldest update first.
type Incident struct {
	ID         string           `json:"id"`
	PageID     string           `json:"page_id"`
	Title      string           `json:"title"`
	Body       string           `json:"body"`
	Status     string           `json:"status"`
	Impact     string           `json:"impact"`
	CreatedBy  string           `json:"created_by"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
	ResolvedAt *time.Time       `json:"resolved_at"`
	Updates    []IncidentUpdate `json:"updates"`
}

// Actor identifies who changes something, for the audit entry.
type Actor struct{ UserID, IP string }

// CheckSource is what the service needs to know about checks. *checks.Service implements it.
type CheckSource interface {
	// ExistingIDs returns the subset of ids that are checks.
	ExistingIDs(ctx context.Context, ids []string) (map[string]bool, error)
	// StatusStates maps every check ID to up, down or unknown (disabled checks are unknown).
	StatusStates(ctx context.Context) (map[string]string, error)
	// DailyUptime returns, for every check, `days` UTC days starting at first (index 0).
	DailyUptime(ctx context.Context, first time.Time, days int) (map[string][]DaySeconds, error)
}

// DaySeconds is the observed up and down time of one check on one UTC day.
type DaySeconds struct{ Up, Down int64 }

// cleanText validates and normalises operator text: valid UTF-8, bounded, and free of control,
// bidirectional-override and zero-width characters. Multi-line text keeps only line feeds.
func cleanText(field, v string, minLen, maxLen int, multiline bool) (string, error) {
	if !utf8.ValidString(v) {
		return "", bad(field, "Use valid text.")
	}
	if multiline {
		out := make([]rune, 0, len(v))
		rs := []rune(v)
		for i := 0; i < len(rs); i++ {
			if rs[i] == '\r' {
				if i+1 < len(rs) && rs[i+1] == '\n' {
					continue
				}
				out = append(out, '\n')
				continue
			}
			out = append(out, rs[i])
		}
		v = string(out)
	}
	v = trimSpace(v)
	n := utf8.RuneCountInString(v)
	if n < minLen {
		return "", bad(field, "This field is required.")
	}
	if n > maxLen {
		return "", bad(field, "Use at most "+strconv.Itoa(maxLen)+" characters.")
	}
	for _, r := range v {
		if r == '\n' && multiline {
			continue
		}
		if unicode.IsControl(r) || hidden(r) {
			return "", bad(field, "Remove control and invisible characters.")
		}
	}
	return v, nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func hidden(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, r >= 0x2028 && r <= 0x202E, r >= 0x2060 && r <= 0x2069, r == 0xFEFF, r == 0x00AD, r == 0xFFFC, r == 0xFFFD:
		return true
	}
	return unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cs, r)
}

func validSlug(s string) error {
	if !SlugPattern.MatchString(s) {
		return bad("slug", "Use 1 to 64 lowercase letters, digits or hyphens, starting and ending with a letter or digit.")
	}
	if reservedSlugs[s] {
		return bad("slug", "This slug is reserved.")
	}
	return nil
}

// normalizePage validates in and returns the cleaned copy. Check existence is verified separately.
func normalizePage(in PageInput) (PageInput, error) {
	var err error
	out := PageInput{Slug: in.Slug, Published: in.Published}
	if out.Title, err = cleanText("title", in.Title, 1, MaxTitle, false); err != nil {
		return out, err
	}
	if out.Description, err = cleanText("description", in.Description, 0, MaxDescription, true); err != nil {
		return out, err
	}
	if len(in.Components) > MaxComponents {
		return out, bad("components", "Use at most "+strconv.Itoa(MaxComponents)+" components.")
	}
	out.Components = make([]ComponentInput, 0, len(in.Components))
	for i, c := range in.Components {
		field := "components[" + strconv.Itoa(i) + "]"
		name, err := cleanText(field+".name", c.Name, 1, MaxComponentName, false)
		if err != nil {
			return out, err
		}
		if len(c.CheckIDs) > MaxChecksPerComp {
			return out, bad(field+".check_ids", "Use at most "+strconv.Itoa(MaxChecksPerComp)+" checks per component.")
		}
		seen := map[string]bool{}
		ids := make([]string, 0, len(c.CheckIDs))
		for _, id := range c.CheckIDs {
			if !checkID.MatchString(id) {
				return out, bad(field+".check_ids", "Choose existing checks.")
			}
			if seen[id] {
				return out, bad(field+".check_ids", "A check can appear once per component.")
			}
			seen[id] = true
			ids = append(ids, id)
		}
		out.Components = append(out.Components, ComponentInput{Name: name, CheckIDs: ids})
	}
	return out, nil
}

func validIncidentStatus(field, s string) error {
	switch s {
	case IncInvestigating, IncIdentified, IncMonitoring, IncResolved:
		return nil
	}
	return bad(field, "Use investigating, identified, monitoring or resolved.")
}

func validImpact(field, s string) error {
	switch s {
	case ImpactNone, ImpactMinor, ImpactMajor:
		return nil
	}
	return bad(field, "Use none, minor or major.")
}
