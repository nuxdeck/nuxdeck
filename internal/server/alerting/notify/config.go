// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// Secret is the write-only credential type shared with checks: a string sets it, the empty
// string clears it, omission or {"set":true} keeps it, and it reads back as {"set":bool}.
type Secret = checks.Secret

// Channel types.
const (
	TypeSMTP     = "smtp"
	TypeSlack    = "slack"
	TypeTeams    = "teams"
	TypeDiscord  = "discord"
	TypeTelegram = "telegram"
	TypeWebhook  = "webhook"
)

// Types lists every channel type.
var Types = []string{TypeSMTP, TypeSlack, TypeTeams, TypeDiscord, TypeTelegram, TypeWebhook}

// FieldError names the field that failed validation.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, msg string) error { return &FieldError{field, msg} }

// Slot is one credential of a channel.
type Slot struct {
	Key      string
	Secret   *Secret
	Required bool
}

// Config is the type-specific part of a channel. Decode builds it strictly from JSON.
type Config interface {
	Type() string
	// Slots lists the credentials in use; the service stores them encrypted.
	Slots() []Slot
	// Validate checks and normalises the configuration. Secrets with new plaintext are checked too.
	Validate() error
}

// Decode reads the configuration of a channel type; unknown fields are an error.
func Decode(typ string, raw json.RawMessage) (Config, error) {
	var c Config
	switch typ {
	case TypeSMTP:
		c = &SMTP{}
	case TypeSlack:
		c = &Slack{}
	case TypeTeams:
		c = &Teams{}
	case TypeDiscord:
		c = &Discord{}
	case TypeTelegram:
		c = &Telegram{}
	case TypeWebhook:
		c = &Webhook{}
	default:
		return nil, bad("type", "Use smtp, slack, teams, discord, telegram or webhook.")
	}
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, bad("config", "The configuration has an unknown or malformed field.")
	}
	return c, nil
}

// ---- SMTP ----

// SMTP security modes.
const (
	SecurityNone     = "none"
	SecuritySTARTTLS = "starttls"
	SecurityTLS      = "tls"
)

// SMTP sends e-mail. Authentication is only ever offered over TLS.
type SMTP struct {
	Host     string   `json:"host"`
	Port     int      `json:"port,omitempty"`
	Security string   `json:"security,omitempty"` // none, starttls (default) or tls
	Username string   `json:"username,omitempty"`
	Password Secret   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// Type implements Config.
func (*SMTP) Type() string { return TypeSMTP }

// Slots implements Config.
func (c *SMTP) Slots() []Slot {
	if c.Username == "" {
		return nil
	}
	return []Slot{{Key: "password", Secret: &c.Password, Required: true}}
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// Validate implements Config.
func (c *SMTP) Validate() error {
	c.Host = strings.TrimSpace(c.Host)
	if !hostPattern.MatchString(c.Host) && net.ParseIP(c.Host) == nil {
		return bad("config.host", "Use a host name or IP address.")
	}
	if c.Security == "" {
		c.Security = SecuritySTARTTLS
	}
	switch c.Security {
	case SecurityNone, SecuritySTARTTLS, SecurityTLS:
	default:
		return bad("config.security", "Use none, starttls or tls.")
	}
	if c.Port == 0 {
		c.Port = map[string]int{SecurityNone: 25, SecuritySTARTTLS: 587, SecurityTLS: 465}[c.Security]
	}
	if c.Port < 1 || c.Port > 65535 {
		return bad("config.port", "Use a port from 1 to 65535.")
	}
	if c.Username != "" && c.Security == SecurityNone {
		return bad("config.security", "Credentials are never sent unencrypted; use starttls or tls, or remove the username.")
	}
	if strings.ContainsAny(c.Username, "\r\n\x00") || len(c.Username) > 256 {
		return bad("config.username", "The username has invalid characters.")
	}
	from, err := bareAddress(c.From)
	if err != nil {
		return bad("config.from", "Use a single e-mail address.")
	}
	c.From = from
	if len(c.To) < 1 || len(c.To) > 20 {
		return bad("config.to", "Give 1 to 20 recipient addresses.")
	}
	for i, t := range c.To {
		a, err := bareAddress(t)
		if err != nil {
			return bad("config.to", "Every recipient must be a single e-mail address.")
		}
		c.To[i] = a
	}
	return nil
}

// bareAddress accepts one plain address and refuses anything with line breaks or display names,
// which is where header injection hides.
func bareAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "\r\n\x00<>,;\"") || len(s) > 254 {
		return "", fmt.Errorf("invalid address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", fmt.Errorf("invalid address")
	}
	return a.Address, nil
}

// ---- webhook-style channels ----

// Slack posts to a Slack incoming webhook (or a compatible service such as Mattermost).
type Slack struct {
	URL Secret `json:"url"`
}

// Teams posts a MessageCard to a Microsoft Teams incoming webhook.
type Teams struct {
	URL Secret `json:"url"`
}

// Discord posts an embed to a Discord webhook.
type Discord struct {
	URL Secret `json:"url"`
}

// Type implements Config.
func (*Slack) Type() string { return TypeSlack }

// Type implements Config.
func (*Teams) Type() string { return TypeTeams }

// Type implements Config.
func (*Discord) Type() string { return TypeDiscord }

// Slots implements Config.
func (c *Slack) Slots() []Slot { return []Slot{{Key: "url", Secret: &c.URL, Required: true}} }

// Slots implements Config.
func (c *Teams) Slots() []Slot { return []Slot{{Key: "url", Secret: &c.URL, Required: true}} }

// Slots implements Config.
func (c *Discord) Slots() []Slot { return []Slot{{Key: "url", Secret: &c.URL, Required: true}} }

// Validate implements Config.
func (c *Slack) Validate() error { return validateURL("config.url", &c.URL, true) }

// Validate implements Config.
func (c *Teams) Validate() error { return validateURL("config.url", &c.URL, true) }

// Validate implements Config.
func (c *Discord) Validate() error { return validateURL("config.url", &c.URL, true) }

// validateURL checks a webhook URL when new plaintext is supplied. Literal IP hosts are also
// checked against the strict policy for fast feedback; the dialer repeats the check on the
// address actually used, which is what stops DNS rebinding.
func validateURL(field string, s *Secret, httpsOnly bool) error {
	if s.Plain == nil || *s.Plain == "" {
		return nil
	}
	u, err := url.Parse(*s.Plain)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || len(*s.Plain) > 2048 {
		return bad(field, "Use a full URL such as https://example.com/hook without credentials.")
	}
	if u.Scheme != "https" && (httpsOnly || u.Scheme != "http") {
		return bad(field, "Use an https URL.")
	}
	if strings.ContainsAny(*s.Plain, "\r\n \t") {
		return bad(field, "The URL must not contain spaces or line breaks.")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && (probe.Policy{AllowPrivate: true}).Check(ip) != nil {
		return bad(field, "That address can never be reached by notifications.")
	}
	return nil
}

// Telegram sends through the Telegram Bot API.
type Telegram struct {
	BotToken Secret `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

var (
	chatIDPattern = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,63})$`)
	tokenPattern  = regexp.MustCompile(`^[0-9]{3,20}:[A-Za-z0-9_-]{20,80}$`)
)

// Type implements Config.
func (*Telegram) Type() string { return TypeTelegram }

// Slots implements Config.
func (c *Telegram) Slots() []Slot {
	return []Slot{{Key: "bot_token", Secret: &c.BotToken, Required: true}}
}

// Validate implements Config.
func (c *Telegram) Validate() error {
	if !chatIDPattern.MatchString(c.ChatID) {
		return bad("config.chat_id", "Use a numeric chat ID or @channelname.")
	}
	if p := c.BotToken.Plain; p != nil && *p != "" && !tokenPattern.MatchString(*p) {
		return bad("config.bot_token", "That does not look like a Telegram bot token.")
	}
	return nil
}

// Header is one request header of a generic webhook; a secret header's value is stored encrypted.
type Header struct {
	Name        string  `json:"name"`
	Value       string  `json:"value,omitempty"`
	Secret      bool    `json:"secret,omitempty"`
	SecretValue *Secret `json:"secret_value,omitempty"`
}

// Webhook posts the documented JSON payload to any URL.
type Webhook struct {
	URL     Secret   `json:"url"`
	Headers []Header `json:"headers,omitempty"`
}

var (
	headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	// forbiddenHeaders are controlled by the HTTP stack or fixed by the payload.
	forbiddenHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "content-type": true, "user-agent": true, "te": true, "trailer": true, "upgrade": true}
)

const maxHeaders = 20

// Type implements Config.
func (*Webhook) Type() string { return TypeWebhook }

// Slots implements Config.
func (c *Webhook) Slots() []Slot {
	out := []Slot{{Key: "url", Secret: &c.URL, Required: true}}
	for i := range c.Headers {
		h := &c.Headers[i]
		if h.Secret {
			if h.SecretValue == nil {
				h.SecretValue = &Secret{}
			}
			out = append(out, Slot{Key: "header:" + strings.ToLower(h.Name), Secret: h.SecretValue, Required: true})
		}
	}
	return out
}

// Validate implements Config.
func (c *Webhook) Validate() error {
	if err := validateURL("config.url", &c.URL, false); err != nil {
		return err
	}
	if len(c.Headers) > maxHeaders {
		return bad("config.headers", "Use at most 20 headers.")
	}
	seen := map[string]bool{}
	for i := range c.Headers {
		h := &c.Headers[i]
		l := strings.ToLower(h.Name)
		switch {
		case !headerName.MatchString(h.Name) || forbiddenHeaders[l]:
			return bad("config.headers", "Header names use letters, digits and hyphens, and may not be Host, Content-Type or similar.")
		case seen[l]:
			return bad("config.headers", "Header names must be unique.")
		case strings.ContainsAny(h.Value, "\r\n\x00") || len(h.Value) > 1024:
			return bad("config.headers", "Header values must be one line of at most 1024 characters.")
		case h.Secret && h.Value != "":
			return bad("config.headers", "A secret header takes secret_value, not value.")
		case !h.Secret && h.SecretValue != nil:
			return bad("config.headers", "secret_value needs secret: true.")
		case h.Secret && h.SecretValue != nil && h.SecretValue.Plain != nil && strings.ContainsAny(*h.SecretValue.Plain, "\r\n\x00"):
			return bad("config.headers", "Header values must be one line.")
		}
		seen[l] = true
	}
	return nil
}
