// SPDX-License-Identifier: AGPL-3.0-only

export type PresetId = '1h' | '6h' | '24h' | '7d';

export const PRESETS: readonly { id: PresetId; label: string; ms: number }[] = [
  { id: '1h', label: '1 hour', ms: 3_600_000 },
  { id: '6h', label: '6 hours', ms: 6 * 3_600_000 },
  { id: '24h', label: '24 hours', ms: 24 * 3_600_000 },
  { id: '7d', label: '7 days', ms: 7 * 24 * 3_600_000 },
];

export type RangeSelection =
  { kind: 'preset'; id: PresetId } | { kind: 'custom'; from: number; to: number };

export interface TimeWindow {
  from: number;
  to: number;
}

export const MIN_SPAN_MS = 60_000;
export const MAX_SPAN_MS = 31 * 24 * 3_600_000;
/** A custom end this far in the future is a typo, not a plan. */
const FUTURE_SLACK_MS = 60_000;

/** Presets are relative to `now` (so they slide on refresh); a custom range is fixed. */
export function resolveRange(sel: RangeSelection, now: number): TimeWindow {
  if (sel.kind === 'custom') return { from: sel.from, to: sel.to };
  const preset = PRESETS.find((p) => p.id === sel.id) ?? PRESETS[0]!;
  return { from: now - preset.ms, to: now };
}

export type CustomRangeResult =
  | { ok: true; range: Extract<RangeSelection, { kind: 'custom' }> }
  | { ok: false; message: string; field: 'from' | 'to' };

/** Validates the two `datetime-local` values ("2026-10-26T10:30", the reader's local time). */
export function parseCustomRange(from: string, to: string, now: number): CustomRangeResult {
  const f = from ? new Date(from).getTime() : NaN;
  const t = to ? new Date(to).getTime() : NaN;
  if (Number.isNaN(f)) return { ok: false, field: 'from', message: 'Enter a start date and time.' };
  if (Number.isNaN(t)) return { ok: false, field: 'to', message: 'Enter an end date and time.' };
  if (t <= f) return { ok: false, field: 'to', message: 'The end must be after the start.' };
  if (t > now + FUTURE_SLACK_MS) {
    return { ok: false, field: 'to', message: 'The end cannot be in the future.' };
  }
  if (t - f < MIN_SPAN_MS) {
    return { ok: false, field: 'to', message: 'Pick a range of at least one minute.' };
  }
  if (t - f > MAX_SPAN_MS) {
    return { ok: false, field: 'to', message: 'Pick a range of 31 days or less.' };
  }
  return { ok: true, range: { kind: 'custom', from: f, to: t } };
}

const pad = (n: number) => String(n).padStart(2, '0');

/** A timestamp as the value of a `datetime-local` input, in local time. */
export function toLocalInput(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const MIN_POINTS = 100;
const MAX_POINTS = 1200;

/**
 * Seconds per point for a chart `widthPx` wide: about one point per two pixels, so a 24h chart asks
 * for hundreds of points rather than the 5,760 raw samples. Never below the agent's 5 s floor.
 */
export function stepFor(spanMs: number, widthPx: number): number {
  const points = Math.min(MAX_POINTS, Math.max(MIN_POINTS, Math.floor(widthPx / 2)));
  return Math.min(86_400, Math.max(5, Math.ceil(spanMs / 1000 / points)));
}

/** Widths are bucketed so that a window resize does not refetch on every pixel. */
export function widthBucket(widthPx: number): number {
  return Math.max(200, Math.ceil(widthPx / 100) * 100);
}

/** Human description of a window, for chart labels. */
export function describeRange(sel: RangeSelection): string {
  if (sel.kind === 'preset') {
    return `last ${PRESETS.find((p) => p.id === sel.id)?.label.toLowerCase() ?? sel.id}`;
  }
  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  return `${fmt.format(sel.from)} to ${fmt.format(sel.to)}`;
}
