// SPDX-License-Identifier: AGPL-3.0-only

// Package notify formats alert notifications and delivers them over SMTP, Slack, Microsoft
// Teams, Discord, Telegram and generic webhooks (ALR-3). Every outbound connection goes
// through the SSRF-guarded dialer of pkg/probe; errors carry stable codes and never the
// destination URL, token or password.
package notify

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Message kinds.
const (
	KindFiring      = "firing"
	KindStillFiring = "still_firing" // a reminder, or the single summary after a silence ended
	KindResolved    = "resolved"
	KindTest        = "test"
)

// SchemaVersion is the version of the generic webhook payload. It changes only with a
// breaking change to the documented schema.
const SchemaVersion = 1

// Message is one notification. Item names, rule names and summaries are untrusted: they
// come from agents, tags and operators, and every formatter escapes them for its target.
type Message struct {
	Kind       string
	AlertID    string
	Severity   string
	RuleID     string
	RuleName   string
	RuleKind   string
	ItemType   string
	ItemID     string
	ItemName   string
	Summary    string
	Link       string // deep link to the item's page in Nux Deck
	Since      time.Time
	ResolvedAt *time.Time
	FlapCount  int
	At         time.Time
}

const maxField = 200

// plain makes untrusted text safe in any target: control characters become spaces, the
// length is bounded, a zero-width space breaks "@name" mentions and bare "scheme://" links.
func plain(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxField {
			b.WriteString("...")
			break
		}
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0, r == ' ', r == ' ':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
		n++
	}
	out := b.String()
	out = strings.ReplaceAll(out, "@", "@\u200b")
	out = strings.ReplaceAll(out, "://", ":\u200b//")
	return out
}

// oneLine is plain with line breaks guaranteed absent; for e-mail headers.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), " ")
}

func (m Message) title() string {
	switch m.Kind {
	case KindResolved:
		return "RESOLVED"
	case KindStillFiring:
		return "STILL FIRING"
	case KindTest:
		return "TEST"
	default:
		return "FIRING"
	}
}

func (m Message) sinceText() string {
	if m.Since.IsZero() {
		return ""
	}
	return m.Since.UTC().Format(time.RFC3339)
}

// color is a per-severity accent as a 24-bit RGB number.
func (m Message) color() int {
	if m.Kind == KindResolved {
		return 0x2e9e5b
	}
	switch m.Severity {
	case "critical":
		return 0xd33f49
	case "warning":
		return 0xe0a030
	default:
		return 0x3b82c4
	}
}

// RedactURL reduces a URL to scheme and host, the only part that is safe to log.
func RedactURL(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return "invalid-url"
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return raw[:i+3] + rest
}
