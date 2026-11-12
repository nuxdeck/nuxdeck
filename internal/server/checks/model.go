// SPDX-License-Identifier: AGPL-3.0-only

// Package checks schedules and records uptime checks (UPT-1 to UPT-3, UPT-5). A check runs
// on the server or on one chosen agent; the probes themselves live in pkg/probe.
package checks

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// RunnerServer is the runner value for checks that run on nuxd itself; any other runner is an agent ID.
const RunnerServer = "server"

// Status of a check as a whole.
const (
	StateUp      = "up"
	StateDown    = "down"
	StateUnknown = "unknown"
)

// Limits (UPT-3).
const (
	MinIntervalS = 20
	MaxIntervalS = 86400
	MaxTimeoutS  = 60
	MaxRetries   = 5
)

// Secret is a write-only credential. On input a JSON string sets or replaces it, the empty
// string clears it, and null, omission or {"set":true} (an echoed GET) keeps what is stored.
// On output it is only ever {"set":true} or {"set":false}.
type Secret struct {
	// Plain is the new value; nil keeps the stored one. A pointer to "" clears it.
	Plain *string `json:"-"`
	// IsSet reports whether a value is stored; it is filled on output.
	IsSet bool `json:"-"`
}

// UnmarshalJSON accepts a string, null or {"set":bool}.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var str *string
	if err := json.Unmarshal(b, &str); err == nil {
		s.Plain = str
		return nil
	}
	var obj struct {
		Set *bool `json:"set"`
	}
	if err := json.Unmarshal(b, &obj); err != nil || obj.Set == nil {
		return errors.New("secret must be a string or {\"set\":true}")
	}
	s.Plain, s.IsSet = nil, *obj.Set
	return nil
}

// MarshalJSON never reveals the value.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Set bool `json:"set"`
	}{s.IsSet})
}

// Header is one request header; a secret header's value is stored encrypted.
type Header struct {
	Name   string  `json:"name"`
	Value  string  `json:"value,omitempty"`
	Secret bool    `json:"secret,omitempty"`
	Set    *Secret `json:"secret_value,omitempty"`
}

// Auth is HTTP basic or bearer authentication.
type Auth struct {
	Type     string  `json:"type"` // none, basic, bearer
	Username string  `json:"username,omitempty"`
	Password *Secret `json:"password,omitempty"`
	Token    *Secret `json:"token,omitempty"`
}

// JSONMatch is the small JSON-path condition of an HTTP check.
type JSONMatch struct {
	Path  string `json:"path"`
	Op    string `json:"op"` // exists, equals
	Value string `json:"value,omitempty"`
}

// HTTPConfig configures an HTTP(S) check.
type HTTPConfig struct {
	URL            string     `json:"url"`
	Method         string     `json:"method,omitempty"`
	Headers        []Header   `json:"headers,omitempty"`
	Body           string     `json:"body,omitempty"`
	Auth           *Auth      `json:"auth,omitempty"`
	ExpectedStatus []int      `json:"expected_status,omitempty"`
	Keyword        string     `json:"keyword,omitempty"`
	JSON           *JSONMatch `json:"json,omitempty"`
	VerifyTLS      *bool      `json:"verify_tls,omitempty"`
	MaxRedirects   *int       `json:"max_redirects,omitempty"`
	MaxBodyBytes   int        `json:"max_body_bytes,omitempty"`
}

// TCPConfig configures a TCP connect check.
type TCPConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// DNSConfig configures a DNS record check.
type DNSConfig struct {
	Name       string   `json:"name"`
	RecordType string   `json:"record_type"`
	Resolver   string   `json:"resolver,omitempty"`
	Expected   []string `json:"expected,omitempty"`
}

// TLSConfig configures a certificate-expiry check.
type TLSConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	WarnDays    *int   `json:"warn_days,omitempty"`
	VerifyChain *bool  `json:"verify_chain,omitempty"`
}

// PingConfig configures an ICMP check.
type PingConfig struct {
	Host  string `json:"host"`
	Count int    `json:"count,omitempty"`
}

// Check is a check as the API reads and writes it.
type Check struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Type         probe.Type  `json:"type"`
	Runner       string      `json:"runner"`
	IntervalS    int         `json:"interval_s"`
	TimeoutS     int         `json:"timeout_s"`
	Retries      int         `json:"retries"`
	Enabled      bool        `json:"enabled"`
	AllowPrivate bool        `json:"allow_private"`
	HTTP         *HTTPConfig `json:"http,omitempty"`
	TCP          *TCPConfig  `json:"tcp,omitempty"`
	DNS          *DNSConfig  `json:"dns,omitempty"`
	TLS          *TLSConfig  `json:"tls,omitempty"`
	Ping         *PingConfig `json:"ping,omitempty"`
	CreatedBy    string      `json:"created_by"`
	UpdatedBy    string      `json:"updated_by"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	// Rev is the version behind the ETag.
	Rev int64 `json:"-"`
}

// Status is the current state of a check.
type Status struct {
	State         string     `json:"state"`
	Since         *time.Time `json:"since"`
	LastChecked   *time.Time `json:"last_checked"`
	LastLatencyMS *int64     `json:"last_latency_ms"`
	LastErrorCode string     `json:"last_error_code"`
	LastDetail    string     `json:"last_detail"`
}

// View is a check with its status, as listed and fetched.
type View struct {
	Check
	Status Status `json:"status"`
}

// ETag identifies the stored version of a check.
func (c Check) ETag() string { return `"c` + itoa(c.Rev) + `"` }

// Result is one recorded run.
type Result struct {
	TS        time.Time `json:"ts"`
	Status    string    `json:"status"`
	LatencyMS int64     `json:"latency_ms"`
	ErrorCode string    `json:"error_code"`
	Detail    string    `json:"detail"`
}

// Uptime holds the uptime percentage over the standard windows; nil means no data.
type Uptime struct {
	H24 *float64 `json:"24h"`
	D7  *float64 `json:"7d"`
	D30 *float64 `json:"30d"`
	D90 *float64 `json:"90d"`
}

// Event is published when a check changes state.
type Event struct {
	CheckID   string
	Name      string
	From, To  string
	At        time.Time
	LatencyMS int64
	ErrorCode string
	Detail    string
}
