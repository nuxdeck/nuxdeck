// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func (r *Runner) runDNS(ctx context.Context, s *DNSSpec) Result {
	var refused atomic.Bool
	res := net.DefaultResolver
	if s.Resolver != "" {
		d := r.Policy.Dialer(0) // the resolver itself is a destination the guard must vet
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, s.Resolver)
			if errors.Is(err, ErrBlocked) {
				refused.Store(true) // the resolver's own error does not wrap ours
			}
			return c, err
		}}
	}
	start := time.Now()
	var got []string
	var err error
	switch strings.ToUpper(s.RecordType) {
	case "A", "AAAA":
		network := "ip4"
		if strings.EqualFold(s.RecordType, "AAAA") {
			network = "ip6"
		}
		var ips []net.IP
		if ips, err = res.LookupIP(ctx, network, s.Name); err == nil {
			for _, ip := range ips {
				got = append(got, ip.String())
			}
		}
	case "CNAME":
		var c string
		if c, err = res.LookupCNAME(ctx, s.Name); err == nil {
			got = []string{c}
		}
	case "TXT":
		got, err = res.LookupTXT(ctx, s.Name)
	case "MX":
		var mx []*net.MX
		if mx, err = res.LookupMX(ctx, s.Name); err == nil {
			for _, m := range mx {
				got = append(got, m.Host)
			}
		}
	default:
		return down(errcode.CHKDNS001, "unsupported record type", 0)
	}
	lat := time.Since(start)
	if err != nil {
		if refused.Load() {
			return down(errcode.CHKNet001, "", lat)
		}
		return down(errcode.CHKDNS001, "", lat)
	}
	if len(got) == 0 {
		return down(errcode.CHKDNS001, "no records", lat)
	}
	for _, want := range s.Expected {
		if !containsFold(got, want) {
			return down(errcode.CHKDNS002, "", lat)
		}
	}
	return Result{Status: StatusUp, Latency: lat}
}

func containsFold(got []string, want string) bool {
	w := strings.TrimSuffix(strings.ToLower(want), ".")
	for _, g := range got {
		if strings.TrimSuffix(strings.ToLower(g), ".") == w {
			return true
		}
	}
	return false
}
