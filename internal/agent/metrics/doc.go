// SPDX-License-Identifier: Apache-2.0

// Package metrics collects host and container metrics, buffers them locally and hands them
// to the stream as MetricBatch messages (MET-1, MET-2, MET-4, AGT-5).
//
// The agent only reads: /proc, /sys/fs/cgroup, statfs and, as a fallback, the container
// stats API through nux-sockguard. Every path is resolved below Config.Root.
//
// # Conventions
//
// Counters are cumulative and monotonic: the agent absorbs resets (a counter that goes
// backwards, for example after a container restart) by carrying on from the last value, so
// the server can apply rate() without special cases. Gauges are instantaneous. Time is in
// seconds, sizes in bytes, ratios are 0..1 (CPU ratios may exceed 1 for a container using
// several cores). Series.Labels carries the dimensions below; Series.Target says host or
// container (the id is the runtime id).
//
// # Host metrics (TARGET_KIND_HOST)
//
//	nux_host_cpu_seconds_total{cpu="all"|"0".."N", mode="user|nice|system|idle|iowait|irq|softirq|steal"}  counter
//	nux_host_cpu_usage_ratio{cpu="all"}                                gauge, 1 - (idle+iowait)/total since the last sample
//	nux_host_load_average{window="1m|5m|15m"}                          gauge
//	nux_host_memory_bytes{type="total|available|free|buffers|cached|used"}  gauge, used = total - available
//	nux_host_swap_bytes{type="total|free|used"}                        gauge
//	nux_host_filesystem_bytes{mount, device, fstype, type="size|used|avail"}  gauge
//	nux_host_disk_io_bytes_total{device, direction="read|write"}       counter
//	nux_host_disk_io_ops_total{device, direction="read|write"}         counter
//	nux_host_disk_io_seconds_total{device}                             counter, time with I/O in flight
//	nux_host_network_bytes_total{interface, direction="rx|tx"}         counter
//	nux_host_network_packets_total{interface, direction="rx|tx"}       counter
//	nux_host_network_errors_total{interface, direction="rx|tx"}        counter
//	nux_host_network_drops_total{interface, direction="rx|tx"}         counter
//
// # Container metrics (TARGET_KIND_CONTAINER, running containers only)
//
//	nux_container_cpu_seconds_total{mode="user|system"}                counter
//	nux_container_cpu_throttled_seconds_total                          counter (cgroups only)
//	nux_container_cpu_usage_ratio                                      gauge, cores in use since the last sample
//	nux_container_memory_bytes{type="usage|working_set|limit"}         gauge; limit is absent when unlimited
//	nux_container_memory_oom_kills_total                               counter (cgroups only)
//	nux_container_blkio_bytes_total{direction="read|write"}            counter
//	nux_container_blkio_ops_total{direction="read|write"}              counter (cgroups only)
//	nux_container_network_bytes_total{direction="rx|tx"}               counter, all interfaces but lo
//	nux_container_network_packets_total{direction="rx|tx"}             counter
//	nux_container_network_errors_total{direction="rx|tx"}              counter
//	nux_container_restart_count                                        gauge, from the inventory
//
// # Delivery
//
// Samples go into a bounded buffer (15 minutes, and a hard cap on the sample count, oldest
// dropped first). A session takes batches from it: samples taken before the session began
// are sent with replayed=true, newer ones live. A batch stays under 1 MB and is removed
// from the buffer only after it was sent. The interval defaults to 15 s and is clamped to
// 5..60 s; HelloAck and ConfigUpdate change it live.
//
// A failing collector never stops the others; its failure is reported as a CollectorError
// (AGT-COL-003 host, AGT-COL-004 containers).
package metrics
