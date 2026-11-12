// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers A, AAAA, CNAME, TXT and MX queries from a table, over UDP on loopback.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]dnsmessage.Resource // key: lower-case name + "/" + type
	hook    func(name string, n int) []dnsmessage.Resource
	queries map[string]int
	addr    string
}

func (f *fakeDNS) setHook(h func(name string, n int) []dnsmessage.Resource) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

func key(name string, t dnsmessage.Type) string { return strings.ToLower(name) + "/" + t.String() }

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{records: map[string][]dnsmessage.Resource{}, queries: map[string]int{}, addr: pc.LocalAddr().String()}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			f.mu.Lock()
			f.queries[q.Name.String()]++
			count := f.queries[q.Name.String()]
			answers := f.records[key(q.Name.String(), q.Type)]
			if f.hook != nil {
				answers = f.hook(q.Name.String(), count)
			}
			f.mu.Unlock()
			rcode := dnsmessage.RCodeSuccess
			if len(answers) == 0 {
				rcode = dnsmessage.RCodeNameError
			}
			msg := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RCode: rcode},
				Questions: []dnsmessage.Question{q}, Answers: answers,
			}
			out, err := msg.Pack()
			if err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return f
}

func rrHeader(name string, t dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET, TTL: 1}
}

func (f *fakeDNS) addA(name, ip string) {
	a := netip.MustParseAddr(ip)
	f.add(name, dnsmessage.TypeA, dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeA), Body: &dnsmessage.AResource{A: a.As4()}})
}

func (f *fakeDNS) addAAAA(name, ip string) {
	a := netip.MustParseAddr(ip)
	f.add(name, dnsmessage.TypeAAAA, dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
}

func (f *fakeDNS) addTXT(name, txt string) {
	f.add(name, dnsmessage.TypeTXT, dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{txt}}})
}

func (f *fakeDNS) addMX(name, host string) {
	f.add(name, dnsmessage.TypeMX, dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeMX), Body: &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName(host)}})
}

func (f *fakeDNS) addCNAME(name, target string) {
	f.add(name, dnsmessage.TypeCNAME, dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}})
}

func (f *fakeDNS) add(name string, t dnsmessage.Type, r dnsmessage.Resource) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[key(name, t)] = append(f.records[key(name, t)], r)
}
