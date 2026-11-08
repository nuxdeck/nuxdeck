// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func (r *Runner) runTLS(ctx context.Context, s *TLSSpec) Result {
	name := s.ServerName
	if name == "" {
		name = s.Host
	}
	cfg := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, InsecureSkipVerify: !s.VerifyChain, Time: r.now} //nolint:gosec // chain verification is a per-check option
	start := time.Now()
	raw, err := r.Policy.Dialer(0).DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return down(classifyNet(err, errcode.CHKTLS001), "", time.Since(start))
	}
	defer func() { _ = raw.Close() }()
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		lat := time.Since(start)
		var (
			unknown x509.UnknownAuthorityError
			host    x509.HostnameError
			inval   x509.CertificateInvalidError
		)
		if errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &inval) {
			return down(errcode.CHKTLS002, "", lat)
		}
		return down(errcode.CHKTLS001, "", lat)
	}
	lat := time.Since(start)
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return down(errcode.CHKTLS001, "no certificate", lat)
	}
	remaining := certs[0].NotAfter.Sub(r.now())
	days := int(remaining.Hours() / 24)
	if remaining <= 0 {
		return down(errcode.CHKTLS003, "expired", lat)
	}
	detail := "days_remaining=" + strconv.Itoa(days)
	if days < s.WarnDays {
		return down(errcode.CHKTLS003, detail, lat)
	}
	return Result{Status: StatusUp, Latency: lat, Detail: detail}
}
