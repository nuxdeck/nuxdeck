// SPDX-License-Identifier: AGPL-3.0-only

import type { AlertItem, AlertItemType, RuleKind, Severity } from '../api/client';
import { auth } from '../auth.svelte';

export const SEVERITIES: readonly Severity[] = ['info', 'warning', 'critical'];

export const RULE_KINDS: readonly { id: RuleKind; label: string }[] = [
  { id: 'check_down', label: 'Check is down' },
  { id: 'host_offline', label: 'Host is offline' },
  { id: 'container_stopped', label: 'Container stopped or restarting' },
  { id: 'metric_threshold', label: 'Metric above a threshold' },
  { id: 'tls_expiring', label: 'Certificate expiring' },
];

export const kindLabel = (kind: string): string =>
  RULE_KINDS.find((k) => k.id === kind)?.label ?? kind;

export const ITEM_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
export const MAX_SELECTOR_ITEMS = 50;

const roles = (): string[] => auth.user?.roles ?? [];

/** Operators and admins may acknowledge alerts and change rules and silences. The server enforces it too. */
export const canOperate = (): boolean => roles().includes('operator') || roles().includes('admin');

/** Channels and routes are admin-only, even to read. */
export const isAdmin = (): boolean => roles().includes('admin');

/**
 * The in-app page of the item an alert is about. The server also sends an absolute `link`, but the UI
 * builds its own route so a link can never leave the app. Null when the ID cannot name an item.
 */
export function itemRoute(type: AlertItemType, id: string): string | null {
  if (!ITEM_ID.test(id)) return null;
  switch (type) {
    case 'host':
      return `/inventory/hosts/${id}`;
    case 'container':
      return `/inventory/containers/${id}`;
    case 'check':
      return `/checks/${id}`;
    default:
      return null;
  }
}

export const alertRoute = (a: Pick<AlertItem, 'item_type' | 'item_id'>): string | null =>
  itemRoute(a.item_type, a.item_id);

export const itemTypeLabel = (t: string): string =>
  t === 'host' ? 'Host' : t === 'container' ? 'Container' : t === 'check' ? 'Check' : t;

// Mirrors inventory.ParseSelector in the server: `key` or `key:value`.
const TAG_KEY = /^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,62}$/;
const TAG_VALUE = /^[A-Za-z0-9_.\-/+@]{1,64}$/;

/** An error message for a tag selector, or null when it is valid. */
export function tagError(text: string): string | null {
  const [key = '', ...rest] = text.split(':');
  const value = rest.join(':');
  if (!TAG_KEY.test(key) || (value !== '' && !TAG_VALUE.test(value))) {
    return 'Use key:value, for example env:production.';
  }
  return null;
}

/** Splits IDs typed separated by commas, spaces or lines. */
export function parseIds(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function idsError(ids: string[]): string | null {
  if (ids.length > MAX_SELECTOR_ITEMS) return 'Use at most 50 item IDs.';
  if (ids.some((id) => !ITEM_ID.test(id)))
    return 'Item IDs are 26 characters, as shown on the item page.';
  return null;
}

export function tagsError(tags: string[]): string | null {
  if (tags.length > MAX_SELECTOR_ITEMS) return 'Use at most 50 tags.';
  const bad = tags.find((t) => tagError(t));
  return bad === undefined
    ? null
    : `"${bad}" is not a valid tag. Use key:value, for example env:production.`;
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

/** "3 minutes ago"; falls back to a dash for a missing or bad timestamp. */
export function since(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const s = Math.round((t - now) / 1000);
  const abs = Math.abs(s);
  if (abs < 60) return rtf.format(s, 'second');
  if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour');
  return rtf.format(Math.round(s / 86400), 'day');
}

export function selectorSummary(s: {
  tags?: string[];
  ids?: string[];
  severity?: string[];
  kinds?: string[];
}): string {
  const parts: string[] = [];
  if (s.tags?.length) parts.push(`tags ${s.tags.join(', ')}`);
  if (s.ids?.length) parts.push(`${s.ids.length} item${s.ids.length === 1 ? '' : 's'}`);
  if (s.severity?.length) parts.push(`severity ${s.severity.join(', ')}`);
  if (s.kinds?.length) parts.push(`rules ${s.kinds.map(kindLabel).join(', ')}`);
  return parts.length ? parts.join('; ') : 'everything';
}
