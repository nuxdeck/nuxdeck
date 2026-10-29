// SPDX-License-Identifier: AGPL-3.0-only

import type { SilenceInput, SilenceKind } from '../api/client';
import { idsError, parseIds, tagsError } from './model';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

// Mirrors internal/server/alerting/model.go.
export const MAX_REASON = 200;
export const MAX_LENGTH_DAYS: Record<SilenceKind, number> = { silence: 30, maintenance: 90 };
export const MAX_AHEAD_DAYS = 365;

export const SILENCE_PRESETS: readonly { hours: number; label: string }[] = [
  { hours: 1, label: '1 hour' },
  { hours: 4, label: '4 hours' },
  { hours: 24, label: '24 hours' },
];

export interface SilenceForm {
  kind: SilenceKind;
  tags: string[];
  ids: string;
  severity: string[];
  kinds: string[];
  /** datetime-local value in the reader's time zone; blank starts now. */
  startsAt: string;
  endsAt: string;
  reason: string;
}

export type SilenceErrors = Record<string, string>;

export const emptySilenceForm = (): SilenceForm => ({
  kind: 'silence',
  tags: [],
  ids: '',
  severity: [],
  kinds: [],
  startsAt: '',
  endsAt: '',
  reason: '',
});

/** A datetime-local value ("2026-10-28T10:30") as a Date, or null when blank or invalid. */
export function parseLocal(value: string): Date | null {
  if (value.trim() === '') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function validateSilence(f: SilenceForm, now: Date = new Date()): SilenceErrors {
  const e: SilenceErrors = {};
  const ids = parseIds(f.ids);
  const tags = tagsError(f.tags);
  if (tags) e['selector.tags'] = tags;
  const idErr = idsError(ids);
  if (idErr) e['selector.ids'] = idErr;
  if (!f.tags.length && !ids.length && !f.severity.length && !f.kinds.length) {
    e.selector = 'Choose at least one tag, item, severity or rule kind to match.';
  }
  const reason = f.reason.trim();
  if (reason === '' || [...reason].length > MAX_REASON) {
    e.reason = 'Give a reason of 1 to 200 characters.';
  }
  const start = parseLocal(f.startsAt);
  if (f.startsAt.trim() !== '' && !start) e.starts_at = 'Enter a valid date and time.';
  const end = parseLocal(f.endsAt);
  if (!end) {
    e.ends_at = 'Enter when it ends.';
  } else {
    const from = start ?? now;
    if (end.getTime() <= now.getTime()) e.ends_at = 'The end must be in the future.';
    else if (end.getTime() <= from.getTime()) e.ends_at = 'The end must be after the start.';
    else if (end.getTime() - from.getTime() > MAX_LENGTH_DAYS[f.kind] * DAY) {
      e.ends_at = `A ${f.kind} may last at most ${MAX_LENGTH_DAYS[f.kind]} days.`;
    }
  }
  if (start && start.getTime() - now.getTime() > MAX_AHEAD_DAYS * DAY) {
    e.starts_at = 'A start may be at most one year ahead.';
  }
  return e;
}

/** Builds the request body. Call only on a form that passed `validateSilence`. */
export function silenceInput(f: SilenceForm): SilenceInput {
  const start = parseLocal(f.startsAt);
  const end = parseLocal(f.endsAt);
  return {
    kind: f.kind,
    selector: {
      tags: [...f.tags],
      ids: parseIds(f.ids),
      severity: [...f.severity],
      kinds: [...f.kinds],
    },
    ...(start ? { starts_at: start.toISOString() } : {}),
    ends_at: (end ?? new Date()).toISOString(),
    reason: f.reason.trim(),
  };
}

/** "Silence this item for N hours": a silence on exactly that item, starting now. */
export function itemSilence(
  itemId: string,
  hours: number,
  itemName: string,
  now: Date = new Date(),
): SilenceInput {
  const reason = `Silenced from the alert page: ${itemName}`;
  return {
    kind: 'silence',
    selector: { ids: [itemId] },
    ends_at: new Date(now.getTime() + hours * HOUR).toISOString(),
    reason: [...reason].slice(0, MAX_REASON).join(''),
  };
}

export const silenceFieldId = (path: string): string =>
  `sil-${path.replace(/[^A-Za-z0-9]+/g, '-').replace(/-$/, '')}`;

/** A Date as a datetime-local value in the reader's time zone. */
export function toLocalInput(d: Date): string {
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
