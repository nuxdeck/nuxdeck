// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Type names a check type.
type Type string

// The check types.
const (
	TypeHTTP Type = "http"
	TypeTCP  Type = "tcp"
	TypeDNS  Type = "dns"
	TypeTLS  Type = "tls"
	TypePing Type = "ping"
)

// Status is the outcome of one run.
type Status string

// Outcomes a probe reports. "unknown" is only ever set by the engine, when no probe ran.
const (
	StatusUp   Status = "up"
	StatusDown Status = "down"
)

// Limits shared by validation and execution.
const (
	DefaultMaxBodyBytes = 64 << 10
	MaxBodyBytesLimit   = 1 << 20
	DefaultRedirects    = 5
	MaxRedirectsLimit   = 10
	MaxDetailBytes      = 200
	MaxPingCount        = 5
)

// Result is what one run produced. Detail is a short note built from fixed vocabulary and
// numbers only; it never contains target content, URLs or credentials.
type Result struct {
	Status  Status
	Latency time.Duration
	Code    errcode.Code
	Detail  string
}

// Spec is one check to run. Exactly the field for Type is set.
type Spec struct {
	Type    Type
	Timeout time.Duration
	HTTP    *HTTPSpec
	TCP     *TCPSpec
	DNS     *DNSSpec
	TLS     *TLSSpec
	Ping    *PingSpec
}

// TCPSpec connects to Host:Port.
type TCPSpec struct {
	Host string
	Port int
}

// DNSSpec resolves Name. RecordType is A, AAAA, CNAME, TXT or MX; Expected values must all be present.
type DNSSpec struct {
	Name       string
	RecordType string
	Resolver   string // host:port, optional
	Expected   []string
}

// TLSSpec reads the certificate of Host:Port and reports down below WarnDays remaining.
type TLSSpec struct {
	Host        string
	Port        int
	ServerName  string
	WarnDays    int
	VerifyChain bool
}

// PingSpec sends Count ICMP echo requests to Host.
type PingSpec struct {
	Host  string
	Count int
}

// Runner executes specs under a Policy. The zero Runner uses the strict server policy.
type Runner struct {
	Policy Policy
	// Now supplies the clock for certificate expiry; nil means time.Now.
	Now func() time.Time
	// ListenPacket opens the ICMP socket; tests replace it. Nil uses unprivileged datagram ICMP.
	ListenPacket func(network, address string) (icmpConn, error)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Run executes the spec, bounded by spec.Timeout and ctx. It always returns a Result.
func (r *Runner) Run(ctx context.Context, s Spec) Result {
	if s.Timeout <= 0 {
		s.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	switch {
	case s.Type == TypeHTTP && s.HTTP != nil:
		return r.runHTTP(ctx, s.HTTP)
	case s.Type == TypeTCP && s.TCP != nil:
		return r.runTCP(ctx, s.TCP)
	case s.Type == TypeDNS && s.DNS != nil:
		return r.runDNS(ctx, s.DNS)
	case s.Type == TypeTLS && s.TLS != nil:
		return r.runTLS(ctx, s.TLS)
	case s.Type == TypePing && s.Ping != nil:
		return r.runPing(ctx, s.Ping)
	}
	return Result{Status: StatusDown, Code: errcode.APIVal001, Detail: "invalid spec"}
}

func down(code errcode.Code, detail string, lat time.Duration) Result {
	return Result{Status: StatusDown, Code: code, Detail: detail, Latency: lat}
}
