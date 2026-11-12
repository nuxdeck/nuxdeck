// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// withClientIP makes the client's address come from the proxy chain when the
// direct peer is a trusted proxy. It rewrites RemoteAddr, the one place every
// handler reads the address from (clientOf). With no trusted proxies nothing
// matches and the header is never read.
func withClientIP(trusted []*net.IPNet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peer, ok := peerAddr(r.RemoteAddr); ok && containsAny(trusted, peer) {
			r.RemoteAddr = clientAddr(peer, r.Header.Get("X-Forwarded-For"), trusted).String()
		}
		next.ServeHTTP(w, r)
	})
}

// clientAddr walks X-Forwarded-For from the right, the hop nearest to nuxd,
// and returns the first address that is not a trusted proxy. A forged entry
// further left is never reached because the walk stops at the first untrusted
// hop. An unparseable entry stops the walk at the peer, which fails closed to
// the proxy's own address rather than an attacker's claim.
func clientAddr(peer netip.Addr, forwardedFor string, trusted []*net.IPNet) netip.Addr {
	if forwardedFor == "" {
		return peer
	}
	entries := strings.Split(forwardedFor, ",")
	leftmost := peer
	for i := len(entries) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			return peer
		}
		addr = addr.Unmap()
		if !containsAny(trusted, addr) {
			return addr
		}
		leftmost = addr
	}
	// Every hop is a trusted proxy: the originating client is the leftmost entry.
	return leftmost
}

func peerAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func containsAny(nets []*net.IPNet, addr netip.Addr) bool {
	ip := net.IP(addr.AsSlice())
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
