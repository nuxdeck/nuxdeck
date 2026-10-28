// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

var local = &Runner{Policy: AgentPolicy()} // loopback test servers are reachable, link-local is not

func httpSpec(h *HTTPSpec) Spec {
	return Spec{Type: TypeHTTP, Timeout: 2 * time.Second, HTTP: h}
}

func wantUp(t *testing.T, r Result) {
	t.Helper()
	if r.Status != StatusUp {
		t.Fatalf("result = %+v, want up", r)
	}
}

func wantDown(t *testing.T, r Result, code errcode.Code) {
	t.Helper()
	if r.Status != StatusDown || r.Code != code {
		t.Fatalf("result = %+v, want down with %s", r, code)
	}
}

func TestUPT1_HTTPStatusKeywordAndJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/teapot":
			w.WriteHeader(http.StatusTeapot)
		case "/json":
			_, _ = w.Write([]byte(`{"a":{"b":[{"c":"ok","n":42,"t":true}]},"s":null}`))
		default:
			_, _ = w.Write([]byte("hello healthy world"))
		}
	}))
	defer srv.Close()
	run := func(h HTTPSpec) Result { h.URL = srv.URL + h.URL; return local.Run(context.Background(), httpSpec(&h)) }

	wantUp(t, run(HTTPSpec{URL: "/"}))
	wantDown(t, run(HTTPSpec{URL: "/teapot"}), errcode.CHKHTTP002)
	wantUp(t, run(HTTPSpec{URL: "/teapot", ExpectedStatus: []int{418}}))
	wantUp(t, run(HTTPSpec{URL: "/", Keyword: "healthy"}))
	wantDown(t, run(HTTPSpec{URL: "/", Keyword: "sick"}), errcode.CHKHTTP003)
	for _, tc := range []struct {
		path, op, val string
		up            bool
	}{
		{"a.b[0].c", JSONEquals, "ok", true},
		{"a.b[0].n", JSONEquals, "42", true},
		{"a.b[0].t", JSONEquals, "true", true},
		{"a.b[0].c", JSONEquals, "nope", false},
		{"a.b[0].c", JSONExists, "", true},
		{"a.b[1].c", JSONExists, "", false},
		{"a.x", JSONExists, "", false},
		{"s", JSONEquals, "null", true},
	} {
		r := run(HTTPSpec{URL: "/json", JSONPath: tc.path, JSONOp: tc.op, JSONValue: tc.val})
		if tc.up {
			wantUp(t, r)
		} else {
			wantDown(t, r, errcode.CHKHTTP004)
		}
	}
	wantDown(t, run(HTTPSpec{URL: "/", JSONPath: "a", JSONOp: JSONExists}), errcode.CHKHTTP004) // not JSON
}

func TestUPT5_HTTPSendsMethodHeadersBodyAndAuth(t *testing.T) {
	var got struct {
		method, auth, custom, body string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		got.method, got.auth, got.custom, got.body = r.Method, r.Header.Get("Authorization"), r.Header.Get("X-Env"), string(b[:n])
	}))
	defer srv.Close()
	r := local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL, Method: "POST", Body: []byte("ping"), Headers: map[string]string{"X-Env": "prod", "Authorization": "Bearer t0k"}}))
	wantUp(t, r)
	if got.method != "POST" || got.auth != "Bearer t0k" || got.custom != "prod" || got.body != "ping" {
		t.Fatalf("server saw %+v", got)
	}
}

func TestUPT1_HTTPRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		_, _ = fmt.Sscanf(r.URL.Path, "/hop/%d", &n)
		if n >= 3 {
			_, _ = w.Write([]byte("end"))
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%s/hop/%d", srv.URL, n+1), http.StatusFound)
	}))
	defer srv.Close()
	wantUp(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL + "/hop/0", MaxRedirects: 3})))
	wantDown(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL + "/hop/0", MaxRedirects: 2})), errcode.CHKHTTP005)
	wantDown(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL + "/hop/0", MaxRedirects: 0})), errcode.CHKHTTP005)
}

func TestUPT1_HTTPBodyCapBoundsWhatIsRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 1000) + "NEEDLE"))
	}))
	defer srv.Close()
	wantUp(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL, Keyword: "NEEDLE", MaxBodyBytes: 2000})))
	wantDown(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL, Keyword: "NEEDLE", MaxBodyBytes: 500})), errcode.CHKHTTP003)
}

func TestUPT3_HTTPTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	r := local.Run(context.Background(), Spec{Type: TypeHTTP, Timeout: 100 * time.Millisecond, HTTP: &HTTPSpec{URL: srv.URL}})
	wantDown(t, r, errcode.CHKHTTP001)
	if r.Detail != "timeout" {
		t.Errorf("detail = %q, want timeout", r.Detail)
	}
}

func TestUPT1_HTTPSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	wantDown(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL, VerifyTLS: true})), errcode.CHKHTTP001)
	wantUp(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL, VerifyTLS: false})))
}

func TestT11_EnvironmentProxyIsIgnored(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	hit := make(chan struct{}, 1)
	go func() {
		if c, err := proxy.Accept(); err == nil {
			hit <- struct{}{}
			_ = c.Close()
		}
	}()
	t.Setenv("HTTP_PROXY", "http://"+proxy.Addr().String())
	t.Setenv("http_proxy", "http://"+proxy.Addr().String())
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	wantUp(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL})))
	select {
	case <-hit:
		t.Fatal("the request went through the environment proxy")
	default:
	}
}

func TestT11_PolicyMatrix(t *testing.T) {
	strict, private := Policy{}, Policy{AllowPrivate: true}
	for _, tc := range []struct {
		ip              string
		strict, private bool // true = allowed
	}{
		{"8.8.8.8", true, true},
		{"2606:4700:4700::1111", true, true},
		{"127.0.0.1", false, false},
		{"::1", false, false},
		{"169.254.169.254", false, false},
		{"169.254.0.1", false, false},
		{"fe80::1", false, false},
		{"fd00:ec2::254", false, false},
		{"100.100.100.200", false, false},
		{"0.0.0.0", false, false},
		{"::", false, false},
		{"224.0.0.1", false, false},
		{"ff02::1", false, false},
		{"255.255.255.255", false, false},
		{"240.0.0.1", false, false},
		{"10.1.2.3", false, true},
		{"172.16.0.1", false, true},
		{"192.168.1.1", false, true},
		{"100.64.0.1", false, true},
		{"fd12:3456::1", false, true},
		{"::ffff:127.0.0.1", false, false},
		{"::ffff:169.254.169.254", false, false},
		{"::ffff:10.0.0.1", false, true},
		{"64:ff9b::7f00:1", false, false},    // NAT64 wrapping 127.0.0.1
		{"64:ff9b::a9fe:a9fe", false, false}, // NAT64 wrapping 169.254.169.254
		{"2002:7f00:1::1", false, false},     // 6to4 wrapping 127.0.0.1
	} {
		ip := netip.MustParseAddr(tc.ip)
		if got := strict.Check(ip) == nil; got != tc.strict {
			t.Errorf("strict.Check(%s) allowed = %v, want %v", tc.ip, got, tc.strict)
		}
		if got := private.Check(ip) == nil; got != tc.private {
			t.Errorf("private.Check(%s) allowed = %v, want %v", tc.ip, got, tc.private)
		}
	}
	if err := AgentPolicy().Check(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("agent policy must allow loopback: %v", err)
	}
	if err := AgentPolicy().Check(netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Error("agent policy must block the metadata address")
	}
}

func TestT11_RunnerRefusesBlockedTargets(t *testing.T) {
	strict := &Runner{}
	for _, u := range []string{
		"http://127.0.0.1:1/", "http://[::1]:1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/", "http://[::ffff:127.0.0.1]:1/",
		"http://localhost:1/", // a name that resolves to loopback
	} {
		wantDown(t, strict.Run(context.Background(), httpSpec(&HTTPSpec{URL: u})), errcode.CHKNet001)
	}
	wantDown(t, strict.Run(context.Background(), Spec{Type: TypeTCP, TCP: &TCPSpec{Host: "127.0.0.1", Port: 1}}), errcode.CHKNet001)
	wantDown(t, strict.Run(context.Background(), Spec{Type: TypeTLS, TLS: &TLSSpec{Host: "169.254.169.254", Port: 443}}), errcode.CHKNet001)
	wantDown(t, strict.Run(context.Background(), Spec{Type: TypePing, Ping: &PingSpec{Host: "127.0.0.1"}}), errcode.CHKNet001)

	// allow_private lets 10.x through the guard: the connection then fails or times out, but is not blocked.
	r := (&Runner{Policy: Policy{AllowPrivate: true}}).Run(context.Background(), Spec{Type: TypeTCP, Timeout: 200 * time.Millisecond, TCP: &TCPSpec{Host: "10.255.255.1", Port: 9}})
	if r.Code == errcode.CHKNet001 {
		t.Fatalf("private range was blocked despite allow_private: %+v", r)
	}
}

func TestT11_RedirectToMetadataIsBlockedAtTheHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	wantDown(t, local.Run(context.Background(), httpSpec(&HTTPSpec{URL: srv.URL, MaxRedirects: 5})), errcode.CHKNet001)
}

func TestT11_RebindingIsDefeatedBecauseTheConnectedAddressIsChecked(t *testing.T) {
	dns := newFakeDNS(t)
	// The first answer is a public address (passes), the next one flips to loopback.
	var flipped atomic.Bool
	dns.setHook(func(_ string, _ int) []dnsmessage.Resource {
		ip := [4]byte{198, 51, 100, 7}
		if flipped.Load() {
			ip = [4]byte{127, 0, 0, 1}
		}
		return []dnsmessage.Resource{{Header: rrHeader("rebind.test.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: ip}}}
	})
	d := Policy{}.Dialer(300 * time.Millisecond)
	d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dns.addr)
	}}
	_, err := d.DialContext(context.Background(), "tcp", "rebind.test:80")
	if errors.Is(err, ErrBlocked) {
		t.Fatalf("a public answer must pass the guard, got %v", err)
	}
	flipped.Store(true)
	_, err = d.DialContext(context.Background(), "tcp", "rebind.test:80")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("after the flip to loopback the dial must be blocked, got %v", err)
	}
}

func TestUPT1_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	wantUp(t, local.Run(context.Background(), Spec{Type: TypeTCP, TCP: &TCPSpec{Host: "127.0.0.1", Port: port}}))
	_ = ln.Close()
	wantDown(t, local.Run(context.Background(), Spec{Type: TypeTCP, TCP: &TCPSpec{Host: "127.0.0.1", Port: port}}), errcode.CHKTCP001)
}

func TestUPT1_DNS(t *testing.T) {
	dns := newFakeDNS(t)
	dns.addA("app.test.", "192.0.2.10")
	dns.addA("app.test.", "192.0.2.11")
	dns.addAAAA("app.test.", "2001:db8::10")
	dns.addTXT("app.test.", "v=spf1 -all")
	dns.addMX("app.test.", "mail.app.test.")
	dns.addCNAME("www.test.", "app.test.")
	run := func(typ string, expected ...string) Result {
		return local.Run(context.Background(), Spec{Type: TypeDNS, Timeout: 2 * time.Second, DNS: &DNSSpec{Name: "app.test", RecordType: typ, Resolver: dns.addr, Expected: expected}})
	}
	wantUp(t, run("A"))
	wantUp(t, run("A", "192.0.2.10", "192.0.2.11"))
	wantDown(t, run("A", "192.0.2.99"), errcode.CHKDNS002)
	wantUp(t, run("AAAA", "2001:db8::10"))
	wantUp(t, run("TXT", "v=spf1 -all"))
	wantUp(t, run("MX", "mail.app.test"))
	wantDown(t, local.Run(context.Background(), Spec{Type: TypeDNS, Timeout: 2 * time.Second, DNS: &DNSSpec{Name: "missing.test", RecordType: "A", Resolver: dns.addr}}), errcode.CHKDNS001)
	// CNAME: Go follows to the canonical name.
	wantUp(t, local.Run(context.Background(), Spec{Type: TypeDNS, Timeout: 2 * time.Second, DNS: &DNSSpec{Name: "www.test", RecordType: "CNAME", Resolver: dns.addr, Expected: []string{"app.test"}}}))
	// A resolver on a forbidden address is refused by the server policy.
	wantDown(t, (&Runner{}).Run(context.Background(), Spec{Type: TypeDNS, Timeout: time.Second, DNS: &DNSSpec{Name: "app.test", RecordType: "A", Resolver: dns.addr}}), errcode.CHKNet001)
}

func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "svc.test"}, DNSNames: []string{"svc.test"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsListener(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestUPT1_TLSExpiry(t *testing.T) {
	now := time.Now()
	port := tlsListener(t, selfSigned(t, now.Add(10*24*time.Hour+time.Hour)))
	run := func(warn int) Result {
		return (&Runner{Policy: AgentPolicy(), Now: func() time.Time { return now }}).Run(context.Background(),
			Spec{Type: TypeTLS, Timeout: 2 * time.Second, TLS: &TLSSpec{Host: "127.0.0.1", Port: port, ServerName: "svc.test", WarnDays: warn}})
	}
	r := run(5)
	wantUp(t, r)
	if r.Detail != "days_remaining=10" {
		t.Errorf("detail = %q", r.Detail)
	}
	r = run(30)
	wantDown(t, r, errcode.CHKTLS003)
	if r.Detail != "days_remaining=10" {
		t.Errorf("detail = %q", r.Detail)
	}
	// An untrusted self-signed chain fails verification when asked to verify.
	r = (&Runner{Policy: AgentPolicy()}).Run(context.Background(), Spec{Type: TypeTLS, Timeout: 2 * time.Second, TLS: &TLSSpec{Host: "127.0.0.1", Port: port, ServerName: "svc.test", VerifyChain: true}})
	wantDown(t, r, errcode.CHKTLS002)

	// An expired certificate is down regardless of the warning window.
	expPort := tlsListener(t, selfSigned(t, now.Add(-time.Hour)))
	r = (&Runner{Policy: AgentPolicy(), Now: func() time.Time { return now }}).Run(context.Background(), Spec{Type: TypeTLS, Timeout: 2 * time.Second, TLS: &TLSSpec{Host: "127.0.0.1", Port: expPort, WarnDays: 0}})
	wantDown(t, r, errcode.CHKTLS003)
	// Not a TLS port at all.
	plain, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = plain.Close() }()
	go func() {
		if c, err := plain.Accept(); err == nil {
			_, _ = c.Write([]byte("SSH-2.0-nope\r\n"))
			_ = c.Close()
		}
	}()
	r = local.Run(context.Background(), Spec{Type: TypeTLS, Timeout: 2 * time.Second, TLS: &TLSSpec{Host: "127.0.0.1", Port: plain.Addr().(*net.TCPAddr).Port}})
	wantDown(t, r, errcode.CHKTLS001)
}

func TestUPT1_PingPermissionDeniedGetsItsOwnCode(t *testing.T) {
	r := &Runner{Policy: AgentPolicy(), ListenPacket: func(string, string) (icmpConn, error) { return nil, fmt.Errorf("listen: %w", syscall.EPERM) }}
	wantDown(t, r.Run(context.Background(), Spec{Type: TypePing, Ping: &PingSpec{Host: "127.0.0.1", Count: 1}}), errcode.CHKPing002)
}

func TestUPT1_PingLoopback(t *testing.T) {
	r := local.Run(context.Background(), Spec{Type: TypePing, Timeout: 2 * time.Second, Ping: &PingSpec{Host: "127.0.0.1", Count: 2}})
	if r.Code == errcode.CHKPing002 {
		t.Skip("environment-limited: net.ipv4.ping_group_range forbids unprivileged ICMP for this user")
	}
	wantUp(t, r)
}

func TestWire_RoundTripAndClamping(t *testing.T) {
	in := Spec{Type: TypeHTTP, Timeout: 5 * time.Second, HTTP: &HTTPSpec{
		URL: "https://x.test/", Method: "POST", Headers: map[string]string{"A": "b"}, Body: []byte("z"), ExpectedStatus: []int{200, 204},
		Keyword: "k", JSONPath: "a.b", JSONOp: JSONEquals, JSONValue: "v", VerifyTLS: true, MaxRedirects: 3, MaxBodyBytes: 1000,
	}}
	out, err := FromProto(ToProto("c1", "r1", in))
	if err != nil {
		t.Fatal(err)
	}
	if out.HTTP.URL != in.HTTP.URL || out.HTTP.JSONValue != "v" || out.HTTP.MaxRedirects != 3 || len(out.HTTP.ExpectedStatus) != 2 || out.Timeout != 5*time.Second {
		t.Fatalf("round trip lost data: %+v", out.HTTP)
	}
	huge := ToProto("c", "r", Spec{Type: TypeHTTP, HTTP: &HTTPSpec{URL: "http://x", MaxRedirects: 1000, MaxBodyBytes: 1 << 30}})
	clamped, _ := FromProto(huge)
	if clamped.HTTP.MaxRedirects != MaxRedirectsLimit || clamped.HTTP.MaxBodyBytes != MaxBodyBytesLimit {
		t.Errorf("limits not clamped: %+v", clamped.HTTP)
	}
	if _, err := FromProto(&agentv1.RunCheck{}); err == nil {
		t.Error("a RunCheck without spec must be refused")
	}
}

func TestParseJSONPath(t *testing.T) {
	for _, ok := range []string{"a", "a.b", "a[0]", "a.b[0].c", "a[0][1]", "x_y.z-1"} {
		if _, err := ParseJSONPath(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".a", "a.", "a..b", "a[", "a[x]", "a[-1]", "a[0]b", "[0]x", strings.Repeat("a", 201)} {
		if _, err := ParseJSONPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
