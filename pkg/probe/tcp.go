// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func (r *Runner) runTCP(ctx context.Context, s *TCPSpec) Result {
	start := time.Now()
	conn, err := r.Policy.Dialer(0).DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	lat := time.Since(start)
	if err != nil {
		return down(classifyNet(err, errcode.CHKTCP001), "", lat)
	}
	_ = conn.Close()
	return Result{Status: StatusUp, Latency: lat}
}
