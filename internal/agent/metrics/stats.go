// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const maxStatsBody = 1 << 20

// statsClient asks the container stats API through nux-sockguard (GET only, the socket is the only peer).
type statsClient struct{ http *http.Client }

func newStatsClient(socket string) *statsClient {
	return &statsClient{http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}}}
}

type statsDoc struct {
	CPU struct {
		Usage struct {
			Total  float64 `json:"total_usage"`
			Kernel float64 `json:"usage_in_kernelmode"`
			User   float64 `json:"usage_in_usermode"`
		} `json:"cpu_usage"`
		Throttling struct {
			Time float64 `json:"throttled_time"`
		} `json:"throttling_data"`
	} `json:"cpu_stats"`
	Memory struct {
		Usage float64            `json:"usage"`
		Limit float64            `json:"limit"`
		Stats map[string]float64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RB float64 `json:"rx_bytes"`
		RP float64 `json:"rx_packets"`
		RE float64 `json:"rx_errors"`
		TB float64 `json:"tx_bytes"`
		TP float64 `json:"tx_packets"`
		TE float64 `json:"tx_errors"`
	} `json:"networks"`
	Blkio struct {
		Bytes []struct {
			Op    string  `json:"op"`
			Value float64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
		Ops []struct {
			Op    string  `json:"op"`
			Value float64 `json:"value"`
		} `json:"io_serviced_recursive"`
	} `json:"blkio_stats"`
}

func (s *statsClient) fetch(ctx context.Context, id string) (*statsDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sockguard/containers/"+url.PathEscape(id)+"/stats?stream=false&one-shot=true", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var d statsDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxStatsBody)).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode stats: %w", err)
	}
	return &d, nil
}

func (s *statsClient) read(ctx context.Context, id string, now time.Time, prev map[string]cpuPrev) ([]reading, error) {
	d, err := s.fetch(ctx, id)
	if err != nil {
		return nil, err
	}
	return d.readings(id, now, prev), nil
}

func (s *statsClient) readNetwork(ctx context.Context, id string) ([]reading, error) {
	d, err := s.fetch(ctx, id)
	if err != nil {
		return nil, err
	}
	return d.network(id), nil
}

func (d *statsDoc) network(id string) []reading {
	var sum netCounters
	if len(d.Networks) == 0 {
		return nil
	}
	for name, n := range d.Networks {
		if name == "lo" {
			continue
		}
		sum.rxBytes += n.RB
		sum.rxPackets += n.RP
		sum.rxErrors += n.RE
		sum.txBytes += n.TB
		sum.txPackets += n.TP
		sum.txErrors += n.TE
	}
	return netReadings([]netCounters{sum}, agentv1.TargetKind_TARGET_KIND_CONTAINER, id, "nux_container_network", "")
}

func (d *statsDoc) readings(id string, now time.Time, prev map[string]cpuPrev) []reading {
	t := agentv1.TargetKind_TARGET_KIND_CONTAINER
	mk := func(metric string, v float64, counter bool, kv ...string) reading {
		return reading{target: t, id: id, metric: metric, labels: lbl(kv...), value: v, counter: counter}
	}
	rs := []reading{
		mk("nux_container_cpu_seconds_total", d.CPU.Usage.User/1e9, true, "mode", "user"),
		mk("nux_container_cpu_seconds_total", d.CPU.Usage.Kernel/1e9, true, "mode", "system"),
		mk("nux_container_memory_bytes", d.Memory.Usage, false, "type", "usage"),
	}
	if inactive, ok := d.Memory.Stats["inactive_file"]; ok {
		rs = append(rs, mk("nux_container_memory_bytes", max(d.Memory.Usage-inactive, 0), false, "type", "working_set"))
	}
	if d.Memory.Limit > 0 && d.Memory.Limit < 1<<62 {
		rs = append(rs, mk("nux_container_memory_bytes", d.Memory.Limit, false, "type", "limit"))
	}
	p, had := prev[id]
	usec := d.CPU.Usage.Total / 1e3
	prev[id] = cpuPrev{usec: usec, at: now}
	if dt := now.Sub(p.at).Seconds(); had && dt > 0 && usec >= p.usec {
		rs = append(rs, mk("nux_container_cpu_usage_ratio", (usec-p.usec)/1e6/dt, false))
	}
	var rb, wb float64
	for _, e := range d.Blkio.Bytes {
		switch strings.ToLower(e.Op) {
		case "read":
			rb += e.Value
		case "write":
			wb += e.Value
		}
	}
	rs = append(rs, mk("nux_container_blkio_bytes_total", rb, true, "direction", "read"), mk("nux_container_blkio_bytes_total", wb, true, "direction", "write"))
	return append(rs, d.network(id)...)
}
