// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics ingests agent metric batches into two embedded Prometheus
// TSDBs (full resolution and 5-minute averages), downsamples hourly, enforces
// retention and answers chart and overview queries (MET-4 to MET-7).
//
// Storage layout under <data_dir>/tsdb:
//
//	full/   every sample as sent by the agent, kept FullRetention (default 15 days)
//	5m/     5-minute averages of full/, kept DownsampledRetention (default 90 days)
//
// Two databases rather than a metric-name suffix because the TSDB library
// expires whole blocks by age: one retention per database is native and needs
// no tombstones. Series carry the same labels in both: __name__ (the agent's
// metric name), target_type ("host" or "container"), target (inventory ID) and,
// for containers, host (the owning host's inventory ID).
package metrics

import (
	"regexp"
	"slices"
	"strings"
)

// Target types, as stored in the target_type label and used by the API.
const (
	TargetHost      = "host"
	TargetContainer = "container"
)

// nameLabel is the TSDB metric-name label.
const nameLabel = "__name__"

// Metric kinds. A counter is cumulative and monotonic; queries return its per-second rate.
const (
	KindGauge   = "gauge"
	KindCounter = "counter"
)

// Def describes one metric the server accepts and serves.
type Def struct {
	Name string
	Kind string
	Unit string // "ratio", "bytes", "seconds", "count", "bytes_per_second" ...
	// Host and Container say which target types the agent reports it for.
	Host      bool
	Container bool
}

func host(name, kind, unit string) Def { return Def{Name: name, Kind: kind, Unit: unit, Host: true} }

func ctr(name, kind, unit string) Def {
	return Def{Name: name, Kind: kind, Unit: unit, Container: true}
}

// catalogue is the single allowlist of metric names, taken from the doc comment of
// internal/agent/metrics. Ingest drops anything else and the query API rejects it.
var catalogue = []Def{
	host("nux_host_cpu_seconds_total", KindCounter, "seconds"),
	host("nux_host_cpu_usage_ratio", KindGauge, "ratio"),
	host("nux_host_load_average", KindGauge, "load"),
	host("nux_host_memory_bytes", KindGauge, "bytes"),
	host("nux_host_swap_bytes", KindGauge, "bytes"),
	host("nux_host_filesystem_bytes", KindGauge, "bytes"),
	host("nux_host_disk_io_bytes_total", KindCounter, "bytes"),
	host("nux_host_disk_io_ops_total", KindCounter, "ops"),
	host("nux_host_disk_io_seconds_total", KindCounter, "seconds"),
	host("nux_host_network_bytes_total", KindCounter, "bytes"),
	host("nux_host_network_packets_total", KindCounter, "packets"),
	host("nux_host_network_errors_total", KindCounter, "packets"),
	host("nux_host_network_drops_total", KindCounter, "packets"),

	ctr("nux_container_cpu_seconds_total", KindCounter, "seconds"),
	ctr("nux_container_cpu_throttled_seconds_total", KindCounter, "seconds"),
	ctr("nux_container_cpu_usage_ratio", KindGauge, "cores"),
	ctr("nux_container_memory_bytes", KindGauge, "bytes"),
	ctr("nux_container_memory_oom_kills_total", KindCounter, "count"),
	ctr("nux_container_blkio_bytes_total", KindCounter, "bytes"),
	ctr("nux_container_blkio_ops_total", KindCounter, "ops"),
	ctr("nux_container_network_bytes_total", KindCounter, "bytes"),
	ctr("nux_container_network_packets_total", KindCounter, "packets"),
	ctr("nux_container_network_errors_total", KindCounter, "packets"),
	ctr("nux_container_restart_count", KindGauge, "count"),
}

// allowedLabels are the dimensions an agent may attach (see the same doc comment). Any other
// label name drops the series, so a buggy or hostile agent cannot invent dimensions.
var allowedLabels = map[string]bool{
	"cpu": true, "mode": true, "type": true, "mount": true, "device": true,
	"fstype": true, "interface": true, "direction": true, "window": true,
}

// Metrics the overview ranking (MET-7) reads.
const (
	hostCPURatio     = "nux_host_cpu_usage_ratio"
	hostMemory       = "nux_host_memory_bytes"
	hostFilesystem   = "nux_host_filesystem_bytes"
	ctrCPURatio      = "nux_container_cpu_usage_ratio"
	ctrMemory        = "nux_container_memory_bytes"
	pressureLookback = 5 * 60 * 1000 // ms of history searched for the latest sample

	maxMetricNameSize = 64
	maxLabelValueSize = 256
)

var catalogueIndex = func() map[string]Def {
	m := make(map[string]Def, len(catalogue))
	for _, d := range catalogue {
		m[d.Name] = d
	}
	return m
}()

// Lookup returns the definition of an allowed metric.
func Lookup(name string) (Def, bool) {
	d, ok := catalogueIndex[name]
	return d, ok
}

// Names lists the allowed metric names, sorted.
func Names() []string {
	out := make([]string, 0, len(catalogue))
	for _, d := range catalogue {
		out = append(out, d.Name)
	}
	slices.Sort(out)
	return out
}

func (d Def) appliesTo(targetType string) bool {
	if targetType == TargetHost {
		return d.Host
	}
	return d.Container
}

// namesRegexp matches every catalogue metric name, for selecting series to downsample.
func namesRegexp() string {
	var b strings.Builder
	for i, n := range Names() {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(regexp.QuoteMeta(n))
	}
	return b.String()
}
