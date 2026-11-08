// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/config"
)

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets, err := config.ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return nets
}

func TestTrustedProxy_ClientAddrWalksRightToFirstUntrusted(t *testing.T) {
	trusted := mustNets(t, "10.0.0.0/8", "2001:db8:1::/48")
	tests := []struct {
		name      string
		peer      string
		forwarded string
		want      string
	}{
		{"single hop", "10.0.0.2", "203.0.113.9", "203.0.113.9"},
		{"forged leftmost entry is ignored", "10.0.0.2", "198.51.100.66, 203.0.113.9", "203.0.113.9"},
		{"trusted hops on the right are skipped", "10.0.0.2", "203.0.113.9, 10.0.0.5, 10.1.2.3", "203.0.113.9"},
		{"unparseable entry fails closed to the peer", "10.0.0.2", "203.0.113.9, not-an-ip", "10.0.0.2"},
		{"all hops trusted yields the leftmost", "10.0.0.2", "10.9.9.9, 10.0.0.5", "10.9.9.9"},
		{"no header yields the peer", "10.0.0.2", "", "10.0.0.2"},
		{"IPv6 client", "2001:db8:1::5", "2001:db8:ffff::7", "2001:db8:ffff::7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer := netip.MustParseAddr(tc.peer)
			if got := clientAddr(peer, tc.forwarded, trusted).String(); got != tc.want {
				t.Errorf("clientAddr(%s, %q) = %s, want %s", tc.peer, tc.forwarded, got, tc.want)
			}
		})
	}
}

func TestTrustedProxy_MiddlewareHonoursHeaderOnlyFromTrustedPeer(t *testing.T) {
	trusted := mustNets(t, "10.0.0.0/8")
	var seen string
	h := withClientIP(trusted, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = clientOf(r).IP
	}))

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{"spoofed header from an untrusted peer is ignored", "198.51.100.10:4433", "203.0.113.1", "198.51.100.10"},
		{"header from a trusted proxy identifies the client", "10.0.0.2:5555", "203.0.113.1", "203.0.113.1"},
		{"IPv4-mapped IPv6 peer is trusted", "[::ffff:10.0.0.2]:5555", "203.0.113.1", "203.0.113.1"},
		{"untrusted peer with no header keeps its address", "198.51.100.10:4433", "", "198.51.100.10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if seen != tc.want {
				t.Errorf("client IP = %q, want %q", seen, tc.want)
			}
		})
	}
}

func TestTrustedProxy_NoTrustedProxiesIgnoresHeader(t *testing.T) {
	h := withClientIP(nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := clientOf(r).IP; got != "10.0.0.2" {
			t.Errorf("client IP = %q, want the peer address; the header must be ignored by default", got)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
}
