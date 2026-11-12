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
	// RFC 8215 local-use NAT64: the IPv4 address may sit in the RFC 6052 /48 layout or in the trailing 32 bits.
	localNAT64 = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	// IPv4-compatible (deprecated ::/96). ::1 is excluded: it is IPv6 loopback, not 0.0.0.1.
	v4Compatible = netip.MustParsePrefix("::/96")
	loopbackV6   = netip.MustParseAddr("::1")
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
	for _, embedded := range embeddedV4(ip) {
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

// embeddedV4 lists the IPv4 addresses that an IPv6 address can reach by translation or
// legacy embedding; every one of them must pass the policy. Under the RFC 6052 /48 layout of
// the local-use NAT64 prefix, an all-zero reading is not a destination, so it is skipped.
func embeddedV4(ip netip.Addr) []netip.Addr {
	if !ip.Is6() || ip == loopbackV6 {
		return nil
	}
	b := ip.As16()
	trailing := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	switch {
	case nat64.Contains(ip), v4Compatible.Contains(ip):
		return []netip.Addr{trailing}
	case localNAT64.Contains(ip):
		rfc6052 := netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]})
		if rfc6052.IsUnspecified() {
			return []netip.Addr{trailing}
		}
		return []netip.Addr{trailing, rfc6052}
	case sixToFour.Contains(ip):
		return []netip.Addr{netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})}
	}
	return nil
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
