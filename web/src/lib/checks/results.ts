// SPDX-License-Identifier: AGPL-3.0-only

import { api, type CheckResult } from '../api/client';
import type { ChartSeries } from '../metrics/series';

/** Results per request; the server caps a page at 500. */
const PAGE = 500;
/** Bounds the work for a 7-day window of a 20-second check (30k rows); the chart then shows the newest part. */
const MAX_PAGES = 12;

/** Reads results newest-first until one older than `fromMs` appears or the page budget is spent. */
export async function fetchResultsSince(
  id: string,
  fromMs: number,
  signal?: AbortSignal,
): Promise<CheckResult[]> {
  const out: CheckResult[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await api.checkResults(id, PAGE, cursor, signal);
    out.push(...res.items);
    const oldest = res.items.at(-1);
    cursor = res.next_cursor;
    if (!cursor || !oldest || Date.parse(oldest.ts) < fromMs) break;
  }
  return out;
}

/** One line of response times (ms) from successful runs inside the window, oldest first. */
export function buildResponseSeries(
  results: CheckResult[],
  fromMs: number,
  toMs: number,
): ChartSeries[] {
  const points: [number, number][] = [];
  for (const r of results) {
    const t = Date.parse(r.ts);
    if (r.status !== 'up' || Number.isNaN(t) || t < fromMs || t > toMs) continue;
    if (!Number.isFinite(r.latency_ms) || r.latency_ms < 0) continue;
    points.push([t, r.latency_ms]);
  }
  points.sort((a, b) => a[0] - b[0]);
  return [{ name: 'Response time', points }];
}

/** The most recent `n` results, oldest first, for the status strip. */
export function recentResults(results: CheckResult[], n: number): CheckResult[] {
  return [...results]
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts))
    .slice(0, n)
    .reverse();
}

/** 99.9 -> "99.9%"; null means no runs fell in the window. */
export function formatUptime(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return 'No data';
  return `${Number(v.toFixed(2))}%`;
}

export function formatLatency(ms: number | null | undefined): string {
  return ms === null || ms === undefined || !Number.isFinite(ms) ? '—' : `${Math.round(ms)} ms`;
}

export function stateLabel(state: string): string {
  switch (state) {
    case 'up':
      return 'Up';
    case 'down':
      return 'Down';
    default:
      return 'Unknown';
  }
}
