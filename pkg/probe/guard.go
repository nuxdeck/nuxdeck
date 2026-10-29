// SPDX-License-Identifier: Apache-2.0

// Package probe runs one uptime check (HTTP(S), TCP, DNS, TLS certificate expiry or ICMP
// ping) and reports up or down with a stable error code. The server and the agent share it.
//
// Every outbound connection goes through a Policy that validates the address actually being
// connected to, not the name that was resolved earlier, so DNS rebinding cannot slip past it.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Policy decides which destination addresses a probe may reach. The zero value is the
// strict server policy: only public unicast addresses.
type Policy struct {
	// AllowPrivate admits RFC 1918, unique-local (fc00::/7) and CGNAT (100.64.0.0/10) ranges.
	AllowPrivate bool
	// AllowLoopback admits loopback addresses. Agents set it, since they run inside the
	// target network and may check local services; the server never does.
	AllowLoopback bool
}

// AgentPolicy is the policy for checks run on an agent: loopback and private ranges are
// the point of running there, but link-local (cloud metadata) stays blocked.
func AgentPolicy() Policy { return Policy{AllowPrivate: true, AllowLoopback: true} }

// ErrBlocked is wrapped by every refusal of the guard.
var ErrBlocked = errors.New("destination address blocked")

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4")
	nat64       = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
	// Metadata endpoints of common clouds that are not link-local; blocked even when private ranges are allowed.
	metadata = []netip.Addr{
		netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
		netip.MustParseAddr("100.100.100.200"), // Alibaba
		netip.MustParseAddr("192.0.0.192"),     // Oracle
	}
)

// Check returns nil if p allows connecting to ip, and an error wrapping ErrBlocked otherwise.
func (p Policy) Check(ip netip.Addr) error {
	ip = ip.Unmap().WithZone("")
	if embedded, ok := embeddedV4(ip); ok {
		if err := p.Check(embedded); err != nil {
			return err
		}
	}
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return blocked(ip, "unspecified or multicast")
	case ip.IsLinkLocalUnicast():
		return blocked(ip, "link-local")
	case thisNetwork.Contains(ip), reserved.Contains(ip):
		return blocked(ip, "reserved")
	}
	for _, m := range metadata {
		if ip == m {
			return blocked(ip, "cloud metadata")
		}
	}
	if ip.IsLoopback() {
		if p.AllowLoopback {
			return nil
		}
		return blocked(ip, "loopback")
	}
	if ip.IsPrivate() || cgnat.Contains(ip) {
		if p.AllowPrivate {
			return nil
		}
		return blocked(ip, "private range")
	}
	if !ip.IsGlobalUnicast() {
		return blocked(ip, "not a public unicast address")
	}
	return nil
}

// embeddedV4 extracts the IPv4 address that NAT64 and 6to4 prefixes smuggle inside an IPv6 one.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

func blocked(ip netip.Addr, why string) error {
	return fmt.Errorf("%w: %s (%s)", ErrBlocked, ip, why)
}

// control is a net.Dialer Control hook. It runs for every connection attempt with the
// resolved address, including each redirect hop and each address of a multi-address name.
func (p Policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address", ErrBlocked)
	}
	return p.Check(ap.Addr())
}

// Dialer returns a dialer that refuses destinations the policy forbids.
func (p Policy) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: p.control}
}

// DialContext is a Dialer-backed dial function for http.Transport and tls.
func (p Policy) DialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.Dialer(timeout).DialContext
}

// classifyNet maps a dial or lookup error to a code, recognising guard refusals.
func classifyNet(err error, fallback errcode.Code) errcode.Code {
	if errors.Is(err, ErrBlocked) {
		return errcode.CHKNet001
	}
	return fallback
}
