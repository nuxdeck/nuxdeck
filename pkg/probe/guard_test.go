// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"errors"
	"net/netip"
	"testing"
)

// T11: the guard unwraps every IPv6 form that embeds an IPv4 address and judges the embedded
// address as if it were connected to directly.
func TestT11_EmbeddedIPv4IsJudgedAsIPv4(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		agent   bool // checked with AgentPolicy (loopback and private allowed) when true, strict policy otherwise
		blocked bool
	}{
		{"ipv4-compatible loopback", "::127.0.0.1", false, true},
		{"ipv4-compatible metadata", "::169.254.169.254", false, true},
		{"ipv4-compatible metadata under agent policy", "::169.254.169.254", true, true},
		{"ipv4-compatible private", "::10.0.0.1", false, true},
		{"ipv4-compatible private allowed for agent", "::10.0.0.1", true, false},
		{"ipv4-compatible public", "::8.8.8.8", false, false},
		{"ipv4-compatible unspecified-network", "::0.0.0.5", false, true},
		{"ipv6 loopback still allowed for agent", "::1", true, false},
		{"ipv6 loopback blocked for server", "::1", false, true},
		{"nat64 well-known loopback", "64:ff9b::7f00:1", false, true},
		{"nat64 well-known metadata", "64:ff9b::a9fe:a9fe", false, true},
		{"nat64 local-use loopback", "64:ff9b:1::7f00:1", false, true},
		{"nat64 local-use loopback under agent policy", "64:ff9b:1::7f00:1", true, false},
		{"nat64 local-use metadata", "64:ff9b:1::a9fe:a9fe", false, true},
		{"6to4 metadata", "2002:a9fe:a9fe::1", false, true},
		{"6to4 public", "2002:0808:0808::1", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{}
			if tt.agent {
				p = AgentPolicy()
			}
			err := p.Check(netip.MustParseAddr(tt.addr))
			if got := err != nil; got != tt.blocked {
				t.Fatalf("Check(%s) blocked=%v (err %v), want %v", tt.addr, got, err, tt.blocked)
			}
			if err != nil && !errors.Is(err, ErrBlocked) {
				t.Fatalf("refusal does not wrap ErrBlocked: %v", err)
			}
		})
	}
}

// T11: RFC 8215 local-use NAT64 (64:ff9b:1::/48) carries the IPv4 address in the RFC 6052 /48
// layout (bytes 6,7,9,10) as well as in the trailing 32 bits. Both readings must pass.
func TestT11_LocalUseNAT64ChecksBothEmbeddingLayouts(t *testing.T) {
	// 64:ff9b:1:a9fe:a9:fe00:: carries 169.254.169.254 in RFC 6052 /48 layout.
	rfc6052Metadata := netip.AddrFrom16([16]byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0xa9, 0xfe, 0x00, 0xa9, 0xfe, 0x00})
	if err := (Policy{}).Check(rfc6052Metadata); !errors.Is(err, ErrBlocked) {
		t.Fatalf("RFC 6052 layout metadata address passed the guard: %v", err)
	}
	trailing := netip.AddrFrom16([16]byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x7f, 0, 0, 1})
	if err := (Policy{}).Check(trailing); !errors.Is(err, ErrBlocked) {
		t.Fatalf("trailing layout loopback passed the strict guard: %v", err)
	}
}

// Ordinary, non-embedding IPv6 addresses keep their existing classification.
func TestT11_NativeIPv6Classification(t *testing.T) {
	tests := []struct {
		addr    string
		blocked bool
	}{
		{"2606:4700:4700::1111", false},
		{"fe80::1", true},
		{"fd00:ec2::254", true},
		{"fd12:3456::1", true},
		{"ff02::1", true},
	}
	for _, tt := range tests {
		err := Policy{}.Check(netip.MustParseAddr(tt.addr))
		if got := err != nil; got != tt.blocked {
			t.Errorf("Check(%s) blocked=%v (err %v), want %v", tt.addr, got, err, tt.blocked)
		}
	}
}
