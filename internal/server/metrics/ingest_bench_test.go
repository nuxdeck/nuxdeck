// SPDX-License-Identifier: AGPL-3.0-only

package metrics_test

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// BenchmarkIngestBatch measures one MetricBatch from a 200-agent fleet, each host reporting 10
// containers at the 15-second cadence. A batch arrives every 15 s / 200 = 75 ms on average, so
// ns/op should stay far below that; the ratio is the server's ingest headroom (NFR-4).
func BenchmarkIngestBatch(b *testing.B) {
	const agents, containersPerAgent = 200, 10
	hosts := make([]inventory.Host, 0, agents)
	var ctrs []inventory.Container
	for a := range agents {
		hostID := fmt.Sprintf("01HOST%020d", a)
		hosts = append(hosts, inventory.Host{ID: hostID, AgentID: fmt.Sprintf("agent-%03d", a), Hostname: fmt.Sprintf("sim-%03d", a), CPUCount: 4, MemoryBytes: 8 << 30, Status: inventory.StatusOnline})
		for c := range containersPerAgent {
			ctrs = append(ctrs, inventory.Container{ID: fmt.Sprintf("01CTR%06d%020d", a, c), HostID: hostID, RuntimeID: fmt.Sprintf("rid-%d-%d", a, c), Name: fmt.Sprintf("svc-%d", c)})
		}
	}
	clk := &clock{t: time.UnixMilli(1_900_000_000_000 - 1_900_000_000_000%300_000)}
	svc, err := metrics.Open(metrics.Options{Dir: b.TempDir(), Log: slog.New(slog.DiscardHandler), Inventory: inventory.NewIndex(hosts, ctrs), Now: clk.now})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = svc.Close() })

	batch := func(a int, ts time.Time) *agentv1.AgentMessage {
		host := &agentv1.Target{Kind: agentv1.TargetKind_TARGET_KIND_HOST}
		ss := []*agentv1.Series{
			{Target: host, Metric: "nux_host_cpu_usage_ratio", Labels: map[string]string{"cpu": "all"}, Points: []*agentv1.Point{pt(ts, 0.1)}},
			{Target: host, Metric: "nux_host_memory_bytes", Labels: map[string]string{"type": "used"}, Points: []*agentv1.Point{pt(ts, 2e9)}},
			{Target: host, Metric: "nux_host_load_average", Labels: map[string]string{"window": "1m"}, Points: []*agentv1.Point{pt(ts, 0.7)}},
		}
		for c := range containersPerAgent {
			target := &agentv1.Target{Kind: agentv1.TargetKind_TARGET_KIND_CONTAINER, Id: fmt.Sprintf("rid-%d-%d", a, c)}
			ss = append(ss,
				&agentv1.Series{Target: target, Metric: "nux_container_cpu_usage_ratio", Points: []*agentv1.Point{pt(ts, 0.02)}},
				&agentv1.Series{Target: target, Metric: "nux_container_memory_bytes", Labels: map[string]string{"type": "working_set"}, Points: []*agentv1.Point{pt(ts, 6e7)}},
			)
		}
		return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Metrics{Metrics: &agentv1.MetricBatch{Series: ss}}}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		// One fleet cycle is 200 batches; advance the clock once per cycle, as agents do.
		if i%agents == 0 && i > 0 {
			clk.add(15 * time.Second)
		}
		msg := batch(i%agents, clk.now())
		b.StartTimer()
		svc.HandleMessage(fmt.Sprintf("agent-%03d", i%agents), msg)
	}
}
