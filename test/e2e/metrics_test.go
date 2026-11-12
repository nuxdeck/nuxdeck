// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"testing"
	"time"
)

// Catalogue names from internal/server/metrics/catalogue.go.
const (
	metricHostCPU       = "nux_host_cpu_usage_ratio"
	metricHostMemory    = "nux_host_memory_bytes"
	metricHostDisk      = "nux_host_filesystem_bytes"
	metricHostNetwork   = "nux_host_network_bytes_total"
	metricContainerCPU  = "nux_container_cpu_usage_ratio"
	metricContainerMem  = "nux_container_memory_bytes"
	metricsWindow       = 10 * time.Minute
	defaultCollectEvery = 15 * time.Second
)

// metricsResult is the part of GET /api/v1/metrics/query the scenarios read.
type metricsResult struct {
	Series []struct {
		Metric string      `json:"metric"`
		Points [][]float64 `json:"points"`
	} `json:"series"`
}

// queryPoints returns the timestamps (unix ms) of every point of metric for one target.
func queryPoints(ctx context.Context, s *stack, target, metric string) ([]float64, error) {
	now := time.Now()
	q := url.Values{
		"target": {target},
		"metric": {metric},
		"from":   {fmt.Sprint(now.Add(-metricsWindow).UnixMilli())},
		"to":     {fmt.Sprint(now.UnixMilli())},
	}
	var res metricsResult
	if err := s.admin.do(ctx, http.MethodGet, "/api/v1/metrics/query?"+q.Encode(), nil, &res); err != nil {
		return nil, err
	}
	var ts []float64
	for _, series := range res.Series {
		for _, p := range series.Points {
			if len(p) == 2 {
				ts = append(ts, p[0])
			}
		}
	}
	sort.Float64s(ts)
	return ts, nil
}

// TestMET1_HostMetricsBecomeQueryable waits for the host series the MET-1 list names to get data.
func TestMET1_HostMetricsBecomeQueryable(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	for _, metric := range []string{metricHostCPU, metricHostMemory, metricHostDisk, metricHostNetwork} {
		metric := metric
		t.Run(metric, func(t *testing.T) {
			eventually(t, 2*time.Minute, metric+" points for "+agentAHostname, func() (bool, string, error) {
				pts, err := queryPoints(ctx, s, s.hostA, metric)
				return len(pts) > 0, fmt.Sprintf("%d points", len(pts)), err
			})
		})
	}
}

// TestMET2_ContainerMetricsBecomeQueryable waits for CPU and memory of the nginx container.
func TestMET2_ContainerMetricsBecomeQueryable(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	for _, metric := range []string{metricContainerCPU, metricContainerMem} {
		metric := metric
		t.Run(metric, func(t *testing.T) {
			eventually(t, 2*time.Minute, metric+" points for nginx", func() (bool, string, error) {
				for _, id := range s.nginx {
					pts, err := queryPoints(ctx, s, id, metric)
					if err == nil && len(pts) > 0 {
						return true, "", nil
					}
				}
				return false, "no nginx record has points yet", nil
			})
		})
	}
}

// TestMET4_CollectionIntervalIsFifteenSeconds samples a host over a minute and requires the default
// 15-second cadence: several points, and no gap between them outside the 5 to 60 second range
// MET-4 allows. The bound is loose enough for scheduling jitter and tight enough to catch a
// collector that stopped or ran far too often.
func TestMET4_CollectionIntervalIsFifteenSeconds(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var ts []float64
	eventually(t, 2*time.Minute, "four host samples", func() (bool, string, error) {
		pts, err := queryPoints(ctx, s, s.hostA, metricHostCPU)
		ts = pts
		return len(pts) >= 4, fmt.Sprintf("%d points", len(pts)), err
	})

	gaps := make([]time.Duration, 0, len(ts))
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, time.Duration(ts[i]-ts[i-1])*time.Millisecond)
	}
	for _, g := range gaps {
		if g < 5*time.Second || g > 60*time.Second {
			t.Errorf("sample gap %s is outside the 5 to 60 second range", g)
		}
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	median := gaps[len(gaps)/2]
	if median < defaultCollectEvery/2 || median > defaultCollectEvery*2 {
		t.Errorf("median sample gap %s is far from the default %s", median, defaultCollectEvery)
	}
	t.Logf("%d samples, median gap %s", len(ts), median)
}
