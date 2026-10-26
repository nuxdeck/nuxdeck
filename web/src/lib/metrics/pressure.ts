// SPDX-License-Identifier: AGPL-3.0-only

import type { Pressure } from '../api/client';

export type Level = 'none' | 'healthy' | 'warning' | 'critical';

/** Thresholds for colouring a percentage; the text always carries the number too. */
export function levelOf(percent: number | null): Level {
  if (percent === null || !Number.isFinite(percent)) return 'none';
  if (percent >= 90) return 'critical';
  if (percent >= 75) return 'warning';
  return 'healthy';
}

export function formatPercent(percent: number | null): string {
  if (percent === null || !Number.isFinite(percent)) return 'no data';
  return `${percent.toFixed(percent < 10 ? 1 : 0)}%`;
}

/** Worst first; rows without any value last; ties and unknowns by name. The server already sorts this way. */
export function rankPressure(rows: Pressure[]): Pressure[] {
  return [...rows].sort((a, b) => {
    if (a.score !== null && b.score !== null && a.score !== b.score) return b.score - a.score;
    if ((a.score === null) !== (b.score === null)) return a.score === null ? 1 : -1;
    return a.name.localeCompare(b.name);
  });
}
