// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// ValidationError names the offending field; Msg comes from this package, never from input.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, msg string) error { return &ValidationError{field, msg} }

var (
	headerName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	hostLabel   = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
	httpMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	recordTypes = []string{"A", "AAAA", "CNAME", "TXT", "MX"}
	// Headers a check may not set: they control framing, routing or hop-by-hop behaviour and enable request smuggling.
	forbiddenHeaders = []string{"host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "expect", "proxy-authorization", "proxy-connection", "content-encoding", "x-forwarded-for", "x-forwarded-host", "forwarded"}
)

// Lengths bounding every free-form field.
const (
	maxName      = 100
	maxURL       = 2048
	maxHeaders   = 20
	maxHeaderVal = 1024
	maxBody      = 4096
	maxKeyword   = 256
	maxExpected  = 10
)

func visible(s string, allowSpace bool) bool {
	for _, r := range s {
		if r == '\t' && allowSpace {
			continue
		}
		if r < 0x20 || r == 0x7f || (r == ' ' && !allowSpace) || r > 0x7e {
			return false
		}
	}
	return true
}

func noControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return utf8.ValidString(s)
}

// validHost accepts an IP literal or a DNS name; no ports, paths, spaces or userinfo.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// Normalize fills defaults and validates c in place. Secrets are not inspected for presence here.
func Normalize(c *Check, policy probe.Policy) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || utf8.RuneCountInString(c.Name) > maxName || !noControl(c.Name) {
		return bad("name", "Use 1 to 100 characters without control characters.")
	}
	if c.IntervalS < MinIntervalS || c.IntervalS > MaxIntervalS {
		return bad("interval_s", "Use 20 seconds to 24 hours (20 to 86400).")
	}
	if c.TimeoutS == 0 {
		c.TimeoutS = min(10, c.IntervalS-1)
	}
	if c.TimeoutS < 1 || c.TimeoutS > MaxTimeoutS || c.TimeoutS >= c.IntervalS {
		return bad("timeout_s", "Use 1 to 60 seconds, shorter than the interval.")
	}
	if c.Retries < 0 || c.Retries > MaxRetries {
		return bad("retries", "Use 0 to 5.")
	}
	if c.Runner == "" {
		c.Runner = RunnerServer
	}
	if c.Runner != RunnerServer && !agentIDPattern.MatchString(c.Runner) {
		return bad("runner", `Use "server" or an agent ID.`)
	}
	// Exactly the section of the type may be present.
	present := map[probe.Type]bool{probe.TypeHTTP: c.HTTP != nil, probe.TypeTCP: c.TCP != nil, probe.TypeDNS: c.DNS != nil, probe.TypeTLS: c.TLS != nil, probe.TypePing: c.Ping != nil}
	has, known := present[c.Type]
	if !known {
		return bad("type", "Use http, tcp, dns, tls or ping.")
	}
	if !has {
		return bad(string(c.Type), "Add the settings object for this check type.")
	}
	for t, p := range present {
		if p && t != c.Type {
			return bad(string(t), "This section does not belong to a "+string(c.Type)+" check.")
		}
	}
	switch c.Type {
	case probe.TypeHTTP:
		return normalizeHTTP(c.HTTP, c.Runner, policy)
	case probe.TypeTCP:
		return hostPort("tcp.host", "tcp.port", c.TCP.Host, c.TCP.Port, c.Runner, policy)
	case probe.TypeDNS:
		return normalizeDNS(c.DNS, c.Runner, policy)
	case probe.TypeTLS:
		t := c.TLS
		if t.Port == 0 {
			t.Port = 443
		}
		if t.WarnDays == nil {
			t.WarnDays = new(14)
		}
		if t.VerifyChain == nil {
			t.VerifyChain = new(true)
		}
		if *t.WarnDays < 0 || *t.WarnDays > 365 {
			return bad("tls.warn_days", "Use 0 to 365.")
		}
		if t.ServerName != "" && !validHost(t.ServerName) {
			return bad("tls.server_name", "Use a host name.")
		}
		return hostPort("tls.host", "tls.port", t.Host, t.Port, c.Runner, policy)
	default: // ping
		p := c.Ping
		if p.Count == 0 {
			p.Count = 3
		}
		if p.Count < 1 || p.Count > probe.MaxPingCount {
			return bad("ping.count", "Use 1 to 5.")
		}
		return hostPort("ping.host", "", p.Host, 1, c.Runner, policy)
	}
}

// hostPort validates a host and port and, for server-run checks, refuses literal addresses the policy forbids.
func hostPort(hostField, portField, host string, port int, runner string, policy probe.Policy) error {
	if !validHost(host) {
		return bad(hostField, "Use a host name or IP address, without scheme, port or path.")
	}
	if portField != "" && (port < 1 || port > 65535) {
		return bad(portField, "Use 1 to 65535.")
	}
	return literalAllowed(hostField, host, runner, policy)
}

func literalAllowed(field, host, runner string, policy probe.Policy) error {
	if runner != RunnerServer {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := policy.Check(ip); err != nil {
			return bad(field, "The server may not check this address. Run the check from an agent, or ask an operator to allow private ranges.")
		}
	}
	return nil
}

func normalizeDNS(d *DNSConfig, runner string, policy probe.Policy) error {
	if !validHost(d.Name) {
		return bad("dns.name", "Use a DNS name.")
	}
	d.RecordType = strings.ToUpper(d.RecordType)
	if !slices.Contains(recordTypes, d.RecordType) {
		return bad("dns.record_type", "Use A, AAAA, CNAME, TXT or MX.")
	}
	if d.Resolver != "" {
		host, port, err := net.SplitHostPort(d.Resolver)
		if err != nil || !validHost(host) {
			return bad("dns.resolver", "Use host:port, for example 9.9.9.9:53.")
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return bad("dns.resolver", "Use host:port, for example 9.9.9.9:53.")
		}
		if err := literalAllowed("dns.resolver", host, runner, policy); err != nil {
			return err
		}
	}
	if len(d.Expected) > maxExpected {
		return bad("dns.expected", "Use at most 10 values.")
	}
	for _, e := range d.Expected {
		if e == "" || len(e) > 255 || !noControl(e) {
			return bad("dns.expected", "Use 1 to 255 characters per value.")
		}
	}
	return nil
}

func normalizeHTTP(h *HTTPConfig, runner string, policy probe.Policy) error {
	if len(h.URL) > maxURL || !visible(h.URL, false) {
		return bad("http.url", "Use a URL of at most 2048 characters without spaces or control characters.")
	}
	u, err := url.Parse(h.URL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return bad("http.url", "Use an absolute http:// or https:// URL.")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return bad("http.url", "Only http and https URLs are allowed.")
	}
	if u.User != nil {
		return bad("http.url", "Remove the user name and password from the URL; use the auth setting.")
	}
	if !validHost(u.Hostname()) {
		return bad("http.url", "The host name is not valid.")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return bad("http.url", "The port is not valid.")
		}
	}
	if err := literalAllowed("http.url", u.Hostname(), runner, policy); err != nil {
		return err
	}
	h.Method = strings.ToUpper(h.Method)
	if h.Method == "" {
		h.Method = "GET"
	}
	if !slices.Contains(httpMethods, h.Method) {
		return bad("http.method", "Use GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS.")
	}
	if len(h.Body) > maxBody || !utf8.ValidString(h.Body) {
		return bad("http.body", "Use at most 4096 characters.")
	}
	if h.Body != "" && (h.Method == "GET" || h.Method == "HEAD") {
		return bad("http.body", "GET and HEAD requests carry no body.")
	}
	if err := normalizeHeaders(h); err != nil {
		return err
	}
	if len(h.ExpectedStatus) > 20 {
		return bad("http.expected_status", "Use at most 20 codes.")
	}
	for _, s := range h.ExpectedStatus {
		if s < 100 || s > 599 {
			return bad("http.expected_status", "Use codes from 100 to 599.")
		}
	}
	if len(h.Keyword) > maxKeyword || !noControl(h.Keyword) {
		return bad("http.keyword", "Use at most 256 characters.")
	}
	if j := h.JSON; j != nil {
		if _, err := probe.ParseJSONPath(j.Path); err != nil {
			return bad("http.json.path", "Use a path such as a.b[0].c.")
		}
		if j.Op != probe.JSONExists && j.Op != probe.JSONEquals {
			return bad("http.json.op", "Use exists or equals.")
		}
		if len(j.Value) > 256 || !noControl(j.Value) || (j.Op == probe.JSONExists && j.Value != "") {
			return bad("http.json.value", "Give a value of at most 256 characters only with equals.")
		}
	}
	if h.VerifyTLS == nil {
		h.VerifyTLS = new(true)
	}
	if h.MaxRedirects == nil {
		h.MaxRedirects = new(probe.DefaultRedirects)
	}
	if *h.MaxRedirects < 0 || *h.MaxRedirects > probe.MaxRedirectsLimit {
		return bad("http.max_redirects", "Use 0 to 10.")
	}
	if h.MaxBodyBytes == 0 {
		h.MaxBodyBytes = probe.DefaultMaxBodyBytes
	}
	if h.MaxBodyBytes < 1 || h.MaxBodyBytes > probe.MaxBodyBytesLimit {
		return bad("http.max_body_bytes", "Use 1 to 1048576.")
	}
	return nil
}

func normalizeHeaders(h *HTTPConfig) error {
	if len(h.Headers) > maxHeaders {
		return bad("http.headers", "Use at most 20 headers.")
	}
	seen := map[string]bool{}
	for i := range h.Headers {
		hd := &h.Headers[i]
		field := "http.headers[" + strconv.Itoa(i) + "]"
		lower := strings.ToLower(hd.Name)
		if !headerName.MatchString(hd.Name) {
			return bad(field+".name", "Use letters, digits and hyphens, up to 64 characters.")
		}
		if slices.Contains(forbiddenHeaders, lower) || strings.HasPrefix(lower, "proxy-") {
			return bad(field+".name", "This header is set by the checker and cannot be overridden.")
		}
		if lower == "authorization" && h.Auth != nil && h.Auth.Type != "" && h.Auth.Type != "none" {
			return bad(field+".name", "Authorization is set by the auth setting.")
		}
		if seen[lower] {
			return bad(field+".name", "Header names must be unique.")
		}
		seen[lower] = true
		if hd.Secret {
			if hd.Value != "" {
				return bad(field+".value", "Send a secret header's value as secret_value.")
			}
			if hd.Set != nil && hd.Set.Plain != nil && !validHeaderValue(*hd.Set.Plain) {
				return bad(field+".secret_value", "Use printable ASCII, up to 1024 characters.")
			}
			if hd.Set == nil {
				hd.Set = &Secret{}
			}
			continue
		}
		if hd.Set != nil {
			return bad(field+".secret_value", "Only secret headers carry a secret_value.")
		}
		if !validHeaderValue(hd.Value) {
			return bad(field+".value", "Use printable ASCII, up to 1024 characters.")
		}
	}
	return normalizeAuth(h)
}

func validHeaderValue(v string) bool { return len(v) <= maxHeaderVal && visible(v, true) }

func normalizeAuth(h *HTTPConfig) error {
	a := h.Auth
	if a == nil {
		return nil
	}
	switch a.Type {
	case "", "none":
		h.Auth = nil
	case "basic":
		if a.Username == "" || len(a.Username) > 128 || strings.Contains(a.Username, ":") || !noControl(a.Username) {
			return bad("http.auth.username", "Use 1 to 128 characters without a colon.")
		}
		if a.Token != nil {
			return bad("http.auth.token", "Basic auth uses a password.")
		}
		if a.Password == nil {
			a.Password = &Secret{}
		}
		if a.Password.Plain != nil && (len(*a.Password.Plain) > 256 || !noControl(*a.Password.Plain)) {
			return bad("http.auth.password", "Use at most 256 characters.")
		}
	case "bearer":
		if a.Username != "" || a.Password != nil {
			return bad("http.auth.type", "Bearer auth uses only a token.")
		}
		if a.Token == nil {
			a.Token = &Secret{}
		}
		if a.Token.Plain != nil && (len(*a.Token.Plain) > 2048 || !visible(*a.Token.Plain, false)) {
			return bad("http.auth.token", "Use printable ASCII without spaces, up to 2048 characters.")
		}
	default:
		return bad("http.auth.type", "Use none, basic or bearer.")
	}
	return nil
}
