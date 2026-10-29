// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// icmpConn is the part of *icmp.PacketConn the pinger uses.
type icmpConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

func (r *Runner) runPing(ctx context.Context, s *PingSpec) Result {
	count := min(max(s.Count, 1), MaxPingCount)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", s.Host)
	if err != nil || len(ips) == 0 {
		return down(errcode.CHKPing001, "no address", 0)
	}
	ip := ips[0].Unmap()
	if err := r.Policy.Check(ip); err != nil {
		return down(errcode.CHKNet001, "", 0)
	}
	network, proto, echoType := "udp4", 1, icmp.Type(ipv4.ICMPTypeEcho)
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	bind := "0.0.0.0"
	if ip.Is6() {
		network, proto, echoType, replyType, bind = "udp6", 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, "::"
	}
	listen := r.ListenPacket
	if listen == nil {
		listen = func(n, a string) (icmpConn, error) { return icmp.ListenPacket(n, a) }
	}
	conn, err := listen(network, bind)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
			return down(errcode.CHKPing002, "", 0)
		}
		return down(errcode.CHKPing001, "socket", 0)
	}
	defer func() { _ = conn.Close() }()

	dst := &net.UDPAddr{IP: ip.AsSlice(), Zone: ip.Zone()}
	id := os.Getpid() & 0xffff
	for seq := 1; seq <= count; seq++ {
		msg := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("nuxdeck")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return down(errcode.CHKPing001, "marshal", 0)
		}
		start := time.Now()
		if _, err := conn.WriteTo(b, dst); err != nil {
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				return down(errcode.CHKPing002, "", 0)
			}
			continue
		}
		if lat, ok := awaitReply(ctx, conn, proto, replyType, seq, start); ok {
			return Result{Status: StatusUp, Latency: lat}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return down(errcode.CHKPing001, "", 0)
}

func awaitReply(ctx context.Context, conn icmpConn, proto int, want icmp.Type, seq int, start time.Time) (time.Duration, bool) {
	buf := make([]byte, 1500)
	// Each echo gets a slice of the remaining time so one lost packet does not eat the budget.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = start.Add(5 * time.Second)
	}
	wait := time.Until(deadline) / 2
	_ = conn.SetReadDeadline(start.Add(max(wait, 200*time.Millisecond)))
	for ctx.Err() == nil {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, false
		}
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || m.Type != want {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && e.Seq == seq {
			return time.Since(start), true
		}
	}
	return 0, false
}
