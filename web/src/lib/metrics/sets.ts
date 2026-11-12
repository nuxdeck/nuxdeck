// SPDX-License-Identifier: AGPL-3.0-only

import type { MetricsResult } from '../api/client';
import { mapValues, percentOf, sumByLabel, type ChartSeries, type Unit } from './series';

export interface QuerySpec {
  key: string;
  metric: string;
  labels?: Record<string, string>;
}

export interface ChartDef {
  id: string;
  title: string;
  unit: Unit;
  /** Fixes the value axis at 0..100 (for percentages). */
  fixedMax?: number;
  queries: QuerySpec[];
  build: (results: Record<string, MetricsResult | undefined>) => ChartSeries[];
}

const first = (r: MetricsResult | undefined): ChartSeries[] =>
  (r?.series ?? []).map((s) => ({ name: '', points: s.points }));

function single(r: MetricsResult | undefined, name: string, fn: (v: number) => number = (v) => v) {
  const s = first(r)[0];
  return s ? [mapValues(s, fn, name)] : [];
}

const NOT_LOOPBACK = (l: Record<string, string>) => l.interface !== 'lo';
const direction = (d: string) =>
  d === 'rx'
    ? 'Received'
    : d === 'tx'
      ? 'Sent'
      : d === 'read'
        ? 'Read'
        : d === 'write'
          ? 'Write'
          : d;

/** Counters arrive as per-second rates of CPU-seconds, so one busy core is 1; divide by the core count. */
export function hostCharts(cpuCount: number): ChartDef[] {
  const cores = Math.max(1, cpuCount);
  return [
    {
      id: 'cpu',
      title: 'CPU usage',
      unit: 'percent',
      fixedMax: 100,
      queries: [
        { key: 'usage', metric: 'nux_host_cpu_usage_ratio', labels: { cpu: 'all' } },
        {
          key: 'iowait',
          metric: 'nux_host_cpu_seconds_total',
          labels: { cpu: 'all', mode: 'iowait' },
        },
        {
          key: 'steal',
          metric: 'nux_host_cpu_seconds_total',
          labels: { cpu: 'all', mode: 'steal' },
        },
      ],
      build: (r) => [
        ...single(r.usage, 'Total', (v) => v * 100),
        ...single(r.iowait, 'I/O wait', (v) => (v / cores) * 100),
        ...single(r.steal, 'Steal', (v) => (v / cores) * 100),
      ],
    },
    {
      id: 'load',
      title: 'Load average',
      unit: 'number',
      queries: [{ key: 'load', metric: 'nux_host_load_average' }],
      build: (r) => sumByLabel(r.load, 'window', (w) => `${w} average`),
    },
    {
      id: 'memory',
      title: 'Memory and swap',
      unit: 'bytes',
      queries: [
        { key: 'used', metric: 'nux_host_memory_bytes', labels: { type: 'used' } },
        { key: 'cached', metric: 'nux_host_memory_bytes', labels: { type: 'cached' } },
        { key: 'swap', metric: 'nux_host_swap_bytes', labels: { type: 'used' } },
      ],
      build: (r) => [
        ...single(r.used, 'Memory used'),
        ...single(r.cached, 'Memory cached'),
        ...single(r.swap, 'Swap used'),
      ],
    },
    {
      id: 'disk-usage',
      title: 'Disk usage per mount',
      unit: 'percent',
      fixedMax: 100,
      queries: [
        { key: 'used', metric: 'nux_host_filesystem_bytes', labels: { type: 'used' } },
        { key: 'size', metric: 'nux_host_filesystem_bytes', labels: { type: 'size' } },
      ],
      build: (r) => percentOf(r.used, r.size, 'mount'),
    },
    {
      id: 'disk-io',
      title: 'Disk I/O',
      unit: 'bytesPerSecond',
      queries: [{ key: 'io', metric: 'nux_host_disk_io_bytes_total' }],
      build: (r) => sumByLabel(r.io, 'direction', direction),
    },
    {
      id: 'network',
      title: 'Network throughput',
      unit: 'bytesPerSecond',
      queries: [{ key: 'net', metric: 'nux_host_network_bytes_total' }],
      build: (r) => sumByLabel(r.net, 'direction', direction, NOT_LOOPBACK),
    },
    {
      id: 'network-errors',
      title: 'Network errors',
      unit: 'perSecond',
      queries: [{ key: 'err', metric: 'nux_host_network_errors_total' }],
      build: (r) => sumByLabel(r.err, 'direction', direction, NOT_LOOPBACK),
    },
  ];
}

export function containerCharts(): ChartDef[] {
  return [
    {
      id: 'cpu',
      title: 'CPU usage',
      unit: 'cores',
      queries: [{ key: 'cpu', metric: 'nux_container_cpu_usage_ratio' }],
      build: (r) => single(r.cpu, 'CPU'),
    },
    {
      id: 'memory',
      title: 'Memory against limit',
      unit: 'bytes',
      queries: [
        { key: 'ws', metric: 'nux_container_memory_bytes', labels: { type: 'working_set' } },
        { key: 'limit', metric: 'nux_container_memory_bytes', labels: { type: 'limit' } },
      ],
      build: (r) => [...single(r.ws, 'Working set'), ...single(r.limit, 'Limit')],
    },
    {
      id: 'network',
      title: 'Network throughput',
      unit: 'bytesPerSecond',
      queries: [{ key: 'net', metric: 'nux_container_network_bytes_total' }],
      build: (r) => sumByLabel(r.net, 'direction', direction),
    },
    {
      id: 'blkio',
      title: 'Block I/O',
      unit: 'bytesPerSecond',
      queries: [{ key: 'io', metric: 'nux_container_blkio_bytes_total' }],
      build: (r) => sumByLabel(r.io, 'direction', direction),
    },
    {
      id: 'restarts',
      title: 'Restarts',
      unit: 'number',
      queries: [{ key: 'restarts', metric: 'nux_container_restart_count' }],
      build: (r) => single(r.restarts, 'Restarts'),
    },
  ];
}
