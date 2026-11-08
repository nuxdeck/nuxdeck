// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"
)

// linkSafe percent-encodes the characters that would end a link in chat markup. The link is
// built from the validated public URL and a ULID, so this is defence in depth.
func linkSafe(l string) string {
	return strings.NewReplacer("<", "%3C", ">", "%3E", "|", "%7C", "\"", "%22", " ", "%20", ")", "%29", "(", "%28").Replace(l)
}

// slackEscape applies Slack's own rule (escape & < >, which neutralises <!channel>, <@U1> and
// <url|text>) on top of plain.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(plain(s))
}

// mdEscape backslash-escapes the markdown that Teams and Discord interpret.
func mdEscape(s string) string {
	return strings.NewReplacer(
		`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "~", `\~`, "|", `\|`, ">", `\>`, "<", `\<`,
		"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "#", `\#`, "!", `\!`,
	).Replace(plain(s))
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil { // only maps and strings go in, so this cannot happen
		return []byte("{}")
	}
	return b
}

// FormatSlack renders an incoming-webhook payload (mrkdwn).
func FormatSlack(m Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*[%s] %s*", m.title(), slackEscape(m.ItemName))
	fmt.Fprintf(&b, "\n*Rule:* %s", slackEscape(m.RuleName))
	fmt.Fprintf(&b, "\n*Severity:* %s | *Item:* %s", slackEscape(m.Severity), slackEscape(m.ItemType))
	if s := m.sinceText(); s != "" {
		fmt.Fprintf(&b, "\n*Since:* %s", s)
	}
	if m.Summary != "" {
		fmt.Fprintf(&b, "\n%s", slackEscape(m.Summary))
	}
	if m.Kind == KindTest {
		b.WriteString("\n_This is a test message from Nux Deck. No alert is firing._")
	}
	if m.Link != "" {
		fmt.Fprintf(&b, "\n<%s|Open in Nux Deck>", linkSafe(m.Link))
	}
	return marshal(map[string]any{"text": b.String(), "link_names": 0, "unfurl_links": false, "unfurl_media": false})
}

// FormatTeams renders a legacy MessageCard, accepted by Microsoft Teams incoming webhooks.
func FormatTeams(m Message) []byte {
	facts := []map[string]string{
		{"name": "Rule", "value": mdEscape(m.RuleName)},
		{"name": "Severity", "value": mdEscape(m.Severity)},
		{"name": "Item", "value": mdEscape(m.ItemType) + ": " + mdEscape(m.ItemName)},
	}
	if s := m.sinceText(); s != "" {
		facts = append(facts, map[string]string{"name": "Since", "value": s})
	}
	section := map[string]any{"facts": facts, "markdown": true}
	text := mdEscape(m.Summary)
	if m.Kind == KindTest {
		text = "This is a test message from Nux Deck. No alert is firing."
	}
	if text != "" {
		section["text"] = text
	}
	card := map[string]any{
		"@type": "MessageCard", "@context": "http://schema.org/extensions",
		"summary":    fmt.Sprintf("[%s] %s", m.title(), mdEscape(m.ItemName)),
		"themeColor": fmt.Sprintf("%06X", m.color()),
		"title":      fmt.Sprintf("[%s] %s", m.title(), mdEscape(m.ItemName)),
		"sections":   []any{section},
	}
	if m.Link != "" {
		card["potentialAction"] = []any{map[string]any{
			"@type": "OpenUri", "name": "Open in Nux Deck",
			"targets": []any{map[string]string{"os": "default", "uri": m.Link}},
		}}
	}
	return marshal(card)
}

// FormatDiscord renders an embed. allowed_mentions is empty, so no text can ping anyone.
func FormatDiscord(m Message) []byte {
	fields := []map[string]any{
		{"name": "Rule", "value": nonEmpty(mdEscape(m.RuleName)), "inline": true},
		{"name": "Severity", "value": nonEmpty(mdEscape(m.Severity)), "inline": true},
		{"name": "Item", "value": nonEmpty(mdEscape(m.ItemType) + ": " + mdEscape(m.ItemName)), "inline": false},
	}
	if s := m.sinceText(); s != "" {
		fields = append(fields, map[string]any{"name": "Since", "value": s, "inline": true})
	}
	desc := mdEscape(m.Summary)
	if m.Kind == KindTest {
		desc = "This is a test message from Nux Deck. No alert is firing."
	}
	embed := map[string]any{
		"title": fmt.Sprintf("[%s] %s", m.title(), mdEscape(m.ItemName)), "description": desc,
		"color": m.color(), "fields": fields,
	}
	if m.Link != "" {
		embed["url"] = m.Link
	}
	if !m.At.IsZero() {
		embed["timestamp"] = m.At.UTC().Format(time.RFC3339)
	}
	return marshal(map[string]any{"embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}})
}

func nonEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// FormatTelegram renders the sendMessage body with HTML parse mode.
func FormatTelegram(chatID string, m Message) []byte {
	e := func(s string) string { return html.EscapeString(plain(s)) }
	var b strings.Builder
	fmt.Fprintf(&b, "<b>[%s] %s</b>", m.title(), e(m.ItemName))
	fmt.Fprintf(&b, "\nRule: %s\nSeverity: %s | Item: %s", e(m.RuleName), e(m.Severity), e(m.ItemType))
	if s := m.sinceText(); s != "" {
		fmt.Fprintf(&b, "\nSince: %s", s)
	}
	if m.Summary != "" {
		fmt.Fprintf(&b, "\n%s", e(m.Summary))
	}
	if m.Kind == KindTest {
		b.WriteString("\n<i>This is a test message from Nux Deck. No alert is firing.</i>")
	}
	if m.Link != "" {
		fmt.Fprintf(&b, "\n<a href=\"%s\">Open in Nux Deck</a>", html.EscapeString(m.Link))
	}
	return marshal(map[string]any{"chat_id": chatID, "text": b.String(), "parse_mode": "HTML", "disable_web_page_preview": true})
}

// WebhookPayload is the documented, versioned body of the generic webhook. Fields are only
// ever added within a schema_version.
type WebhookPayload struct {
	SchemaVersion int          `json:"schema_version"`
	Type          string       `json:"type"` // alert.firing, alert.still_firing, alert.resolved, test
	SentAt        string       `json:"sent_at"`
	Test          bool         `json:"test"`
	Alert         WebhookAlert `json:"alert"`
}

// WebhookAlert is the alert inside a WebhookPayload.
type WebhookAlert struct {
	ID         string      `json:"id"`
	State      string      `json:"state"` // firing or resolved
	Severity   string      `json:"severity"`
	Rule       WebhookRule `json:"rule"`
	Item       WebhookItem `json:"item"`
	Summary    string      `json:"summary"`
	Since      *string     `json:"since"`
	ResolvedAt *string     `json:"resolved_at"`
	FlapCount  int         `json:"flap_count"`
	Link       string      `json:"link"`
}

// WebhookRule identifies the rule.
type WebhookRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// WebhookItem identifies the host, container or check.
type WebhookItem struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// FormatWebhook renders the generic webhook body. Values are raw (JSON-encoded, not escaped for a
// markup language): the receiver owns their interpretation.
func FormatWebhook(m Message) []byte {
	state := "firing"
	typ := "alert." + m.Kind
	if m.Kind == KindResolved {
		state = "resolved"
	}
	if m.Kind == KindTest {
		typ = "test"
	}
	at := m.At
	if at.IsZero() {
		at = time.Now()
	}
	p := WebhookPayload{
		SchemaVersion: SchemaVersion, Type: typ, SentAt: at.UTC().Format(time.RFC3339), Test: m.Kind == KindTest,
		Alert: WebhookAlert{
			ID: m.AlertID, State: state, Severity: m.Severity, FlapCount: m.FlapCount, Link: m.Link, Summary: oneLine(m.Summary),
			Rule: WebhookRule{ID: m.RuleID, Name: m.RuleName, Kind: m.RuleKind},
			Item: WebhookItem{Type: m.ItemType, ID: m.ItemID, Name: m.ItemName},
		},
	}
	if !m.Since.IsZero() {
		s := m.Since.UTC().Format(time.RFC3339)
		p.Alert.Since = &s
	}
	if m.ResolvedAt != nil {
		s := m.ResolvedAt.UTC().Format(time.RFC3339)
		p.Alert.ResolvedAt = &s
	}
	return marshal(p)
}

// EmailSubject is a single line with no CR or LF.
func EmailSubject(m Message) string {
	return oneLine(fmt.Sprintf("[Nux Deck] %s %s: %s - %s", m.title(), m.Severity, plainNoMention(m.ItemName), plainNoMention(m.RuleName)))
}

func plainNoMention(s string) string { return oneLine(plain(s)) }

// EmailBody is the plain-text body, including the deep link.
func EmailBody(m Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n", m.title(), oneLine(plain(m.ItemName)))
	fmt.Fprintf(&b, "Rule:     %s\nSeverity: %s\nItem:     %s\n", oneLine(plain(m.RuleName)), oneLine(m.Severity), oneLine(m.ItemType))
	if s := m.sinceText(); s != "" {
		fmt.Fprintf(&b, "Since:    %s\n", s)
	}
	if m.ResolvedAt != nil {
		fmt.Fprintf(&b, "Resolved: %s\n", m.ResolvedAt.UTC().Format(time.RFC3339))
	}
	if m.Summary != "" {
		fmt.Fprintf(&b, "\n%s\n", oneLine(plain(m.Summary)))
	}
	if m.Kind == KindTest {
		b.WriteString("\nThis is a test message from Nux Deck. No alert is firing.\n")
	}
	if m.Link != "" {
		if _, err := url.Parse(m.Link); err == nil {
			fmt.Fprintf(&b, "\nOpen in Nux Deck: %s\n", oneLine(m.Link))
		}
	}
	return b.String()
}
