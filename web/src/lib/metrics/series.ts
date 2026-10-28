// SPDX-License-Identifier: AGPL-3.0-only

import type { MetricSeries, MetricsResult } from '../api/client';
import { formatBytes } from '../format';

export type Unit =
  'percent' | 'bytes' | 'bytesPerSecond' | 'perSecond' | 'cores' | 'milliseconds' | 'number';

/** One line on a chart: points are [unix_ms, value], ascending in time. */
export interface ChartSeries {
  name: string;
  points: [number, number][];
}

/** uPlot's column layout: x in unix seconds, then one array per series with null for gaps. */
export type Aligned = [number[], ...(number | null)[][]];

/** Merges series onto the union of their timestamps. Linear in the total number of points. */
export function alignSeries(series: ChartSeries[]): Aligned {
  const stamps = new Set<number>();
  for (const s of series) for (const [t] of s.points) stamps.add(t);
  const xs = Float64Array.from(stamps).sort();
  const columns = series.map((s) => {
    const col: (number | null)[] = new Array<number | null>(xs.length).fill(null);
    let j = 0;
    for (const [t, v] of s.points) {
      while (j < xs.length && xs[j]! < t) j++;
      if (xs[j] === t) col[j] = Number.isFinite(v) ? v : null;
    }
    return col;
  });
  return [Array.from(xs, (t) => t / 1000), ...columns];
}

export function hasData(series: ChartSeries[]): boolean {
  return series.some((s) => s.points.length > 0);
}

/** Maps every value of a series. */
export function mapValues(s: ChartSeries, fn: (v: number) => number, name = s.name): ChartSeries {
  return { name, points: s.points.map(([t, v]) => [t, fn(v)]) };
}

/** Sums series point by point (matching timestamps), for example interfaces into one total. */
export function sumSeries(name: string, parts: MetricSeries[]): ChartSeries {
  const total = new Map<number, number>();
  for (const p of parts) for (const [t, v] of p.points) total.set(t, (total.get(t) ?? 0) + v);
  return { name, points: [...total.entries()].sort((a, b) => a[0] - b[0]) };
}

/** Groups a result by a label and sums within each group, ordered by group name. */
export function sumByLabel(
  result: MetricsResult | undefined,
  label: string,
  nameOf: (value: string) => string = (v) => v,
  keep: (labels: Record<string, string>) => boolean = () => true,
): ChartSeries[] {
  const groups = new Map<string, MetricSeries[]>();
  for (const s of result?.series ?? []) {
    if (!keep(s.labels)) continue;
    const key = s.labels[label] ?? '';
    groups.set(key, [...(groups.get(key) ?? []), s]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, parts]) => sumSeries(nameOf(key), parts));
}

/** numerator / denominator × 100, per label value, on matching timestamps. */
export function percentOf(
  numerator: MetricsResult | undefined,
  denominator: MetricsResult | undefined,
  label: string,
  nameOf: (value: string) => string = (v) => v,
): ChartSeries[] {
  const dens = new Map((denominator?.series ?? []).map((s) => [s.labels[label] ?? '', s.points]));
  const out: ChartSeries[] = [];
  for (const s of numerator?.series ?? []) {
    const key = s.labels[label] ?? '';
    const den = new Map(dens.get(key) ?? []);
    const points: [number, number][] = [];
    for (const [t, v] of s.points) {
      const d = den.get(t);
      if (d !== undefined && d > 0) points.push([t, (v / d) * 100]);
    }
    out.push({ name: nameOf(key), points });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export function formatValue(unit: Unit, v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return 'no data';
  switch (unit) {
    case 'percent':
      return `${v.toFixed(v < 10 ? 1 : 0)}%`;
    case 'bytes':
      return formatBytes(v);
    case 'bytesPerSecond':
      return `${formatBytes(v)}/s`;
    case 'perSecond':
      return `${compact(v)}/s`;
    case 'milliseconds':
      return `${Math.round(v)} ms`;
    case 'cores':
      return `${v.toFixed(2)} ${v === 1 ? 'core' : 'cores'}`;
    default:
      return compact(v);
  }
}

function compact(v: number): string {
  const abs = Math.abs(v);
  if (abs >= 100) return v.toFixed(0);
  if (abs >= 10) return v.toFixed(1);
  if (abs === 0) return '0';
  return v.toFixed(2);
}

export interface SeriesStats {
  name: string;
  latest: number | null;
  min: number | null;
  avg: number | null;
  max: number | null;
}

export function summarize(series: ChartSeries[]): SeriesStats[] {
  return series.map((s) => {
    if (s.points.length === 0) {
      return { name: s.name, latest: null, min: null, avg: null, max: null };
    }
    let min = Infinity;
    let max = -Infinity;
    let sum = 0;
    for (const [, v] of s.points) {
      if (v < min) min = v;
      if (v > max) max = v;
      sum += v;
    }
    return {
      name: s.name,
      latest: s.points[s.points.length - 1]![1],
      min,
      avg: sum / s.points.length,
      max,
    };
  });
}

/** One sentence per chart for the accessible name: the first series' latest value and overall peak. */
export function describeStats(unit: Unit, stats: SeriesStats[]): string {
  const withData = stats.filter((s) => s.latest !== null);
  if (withData.length === 0) return 'No data in this range.';
  return withData
    .map(
      (s) =>
        `${s.name}: latest ${formatValue(unit, s.latest)}, highest ${formatValue(unit, s.max)}`,
    )
    .join('; ');
}
