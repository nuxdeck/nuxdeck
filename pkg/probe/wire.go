// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"errors"
	"time"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// ToProto builds the RunCheck message for spec.
func ToProto(checkID, runID string, s Spec) *agentv1.RunCheck {
	m := &agentv1.RunCheck{CheckId: checkID, RunId: runID, TimeoutMs: uint32(s.Timeout.Milliseconds())} //nolint:gosec // bounded by validation
	switch {
	case s.HTTP != nil:
		h := s.HTTP
		p := &agentv1.HttpCheck{
			Url: h.URL, Method: h.Method, Headers: h.Headers, VerifyTls: h.VerifyTLS, Body: h.Body, Keyword: h.Keyword,
			JsonPath: h.JSONPath, JsonOp: h.JSONOp, JsonValue: h.JSONValue,
			MaxRedirects: uint32(h.MaxRedirects), MaxBodyBytes: uint32(h.MaxBodyBytes), //nolint:gosec // bounded by validation
		}
		for _, c := range h.ExpectedStatus {
			p.ExpectedStatus = append(p.ExpectedStatus, uint32(c)) //nolint:gosec // 100-599
		}
		m.Spec = &agentv1.RunCheck_Http{Http: p}
	case s.TCP != nil:
		m.Spec = &agentv1.RunCheck_Tcp{Tcp: &agentv1.TcpCheck{Host: s.TCP.Host, Port: uint32(s.TCP.Port)}} //nolint:gosec // 1-65535
	case s.DNS != nil:
		m.Spec = &agentv1.RunCheck_Dns{Dns: &agentv1.DnsCheck{Name: s.DNS.Name, RecordType: s.DNS.RecordType, Resolver: s.DNS.Resolver, Expected: s.DNS.Expected}}
	case s.TLS != nil:
		m.Spec = &agentv1.RunCheck_Tls{Tls: &agentv1.TlsCheck{Host: s.TLS.Host, Port: uint32(s.TLS.Port), WarnDays: uint32(s.TLS.WarnDays), VerifyChain: s.TLS.VerifyChain, ServerName: s.TLS.ServerName}} //nolint:gosec // bounded
	case s.Ping != nil:
		m.Spec = &agentv1.RunCheck_Ping{Ping: &agentv1.PingCheck{Host: s.Ping.Host, Count: uint32(s.Ping.Count)}} //nolint:gosec // 1-5
	}
	return m
}

// FromProto converts a RunCheck back to a Spec. Limits are clamped here because the sender is
// authenticated but its messages are validated like any input.
func FromProto(m *agentv1.RunCheck) (Spec, error) {
	s := Spec{Timeout: time.Duration(m.GetTimeoutMs()) * time.Millisecond}
	switch sp := m.GetSpec().(type) {
	case *agentv1.RunCheck_Http:
		h := sp.Http
		out := &HTTPSpec{
			URL: h.GetUrl(), Method: h.GetMethod(), Headers: h.GetHeaders(), VerifyTLS: h.GetVerifyTls(), Body: h.GetBody(),
			Keyword: h.GetKeyword(), JSONPath: h.GetJsonPath(), JSONOp: h.GetJsonOp(), JSONValue: h.GetJsonValue(),
			MaxRedirects: min(int(h.GetMaxRedirects()), MaxRedirectsLimit), MaxBodyBytes: min(int(h.GetMaxBodyBytes()), MaxBodyBytesLimit),
		}
		for _, c := range h.GetExpectedStatus() {
			out.ExpectedStatus = append(out.ExpectedStatus, int(c))
		}
		s.Type, s.HTTP = TypeHTTP, out
	case *agentv1.RunCheck_Tcp:
		s.Type, s.TCP = TypeTCP, &TCPSpec{Host: sp.Tcp.GetHost(), Port: int(sp.Tcp.GetPort())}
	case *agentv1.RunCheck_Dns:
		s.Type, s.DNS = TypeDNS, &DNSSpec{Name: sp.Dns.GetName(), RecordType: sp.Dns.GetRecordType(), Resolver: sp.Dns.GetResolver(), Expected: sp.Dns.GetExpected()}
	case *agentv1.RunCheck_Tls:
		t := sp.Tls
		s.Type, s.TLS = TypeTLS, &TLSSpec{Host: t.GetHost(), Port: int(t.GetPort()), ServerName: t.GetServerName(), WarnDays: int(t.GetWarnDays()), VerifyChain: t.GetVerifyChain()}
	case *agentv1.RunCheck_Ping:
		s.Type, s.Ping = TypePing, &PingSpec{Host: sp.Ping.GetHost(), Count: int(sp.Ping.GetCount())}
	default:
		return Spec{}, errors.New("RunCheck has no spec")
	}
	return s, nil
}
