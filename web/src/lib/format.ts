// SPDX-License-Identifier: AGPL-3.0-only

import type { Port } from './api/client';

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

/** 17179869184 -> "16 GiB". */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${Number(value.toFixed(digits))} ${UNITS[unit]}`;
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** An ISO timestamp in the reader's locale, or a dash when there is none. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? '—' : dateTime.format(t);
}

/** "0.0.0.0:8080→80/tcp", or "80/tcp" for a port that is not published. */
export function formatPort(p: Port): string {
  const host = p.host_ip.includes(':') ? `[${p.host_ip}]` : p.host_ip;
  return `${host}:${p.host_port}→${p.container_port}/${p.protocol}`;
}

/** Fact keys the agent sends, shown with friendly labels. */
export function parseDisks(
  json: string | undefined,
): { mount: string; fstype: string; total: number }[] {
  if (!json) return [];
  try {
    const raw = JSON.parse(json) as { mount?: unknown; fstype?: unknown; total_bytes?: unknown }[];
    return raw
      .filter((d) => typeof d.mount === 'string' && typeof d.total_bytes === 'number')
      .map((d) => ({
        mount: String(d.mount),
        fstype: String(d.fstype ?? ''),
        total: Number(d.total_bytes),
      }));
  } catch {
    return [];
  }
}

/** The agent's boot-time fact (Unix seconds) as an ISO string. */
export function bootTimeISO(facts: Record<string, string>): string | null {
  const secs = Number(facts.boot_time_unix);
  return Number.isFinite(secs) && secs > 0 ? new Date(secs * 1000).toISOString() : null;
}
