// SPDX-License-Identifier: AGPL-3.0-only

import type { Channel, RouteEntry } from '../api/client';
import { tagsError } from './model';

export const MAX_ROUTES = 100;

export interface RouteDraft {
  /** A stable key for the keyed list; not sent to the server. */
  key: number;
  tags: string[];
  severity: string[];
  kinds: string[];
  channelId: string;
  cont: boolean;
}

let seq = 0;

export function draftFrom(r?: RouteEntry, channelId = ''): RouteDraft {
  return {
    key: ++seq,
    tags: [...(r?.selector.tags ?? [])],
    severity: [...(r?.selector.severity ?? [])],
    kinds: [...(r?.selector.kinds ?? [])],
    channelId: r?.channel_id ?? channelId,
    cont: r?.continue ?? false,
  };
}

/** A new list with the item at `from` moved by `delta` places; the same list when it cannot move. */
export function move<T>(list: readonly T[], from: number, delta: number): T[] {
  const to = from + delta;
  if (from < 0 || from >= list.length || to < 0 || to >= list.length) return [...list];
  const next = [...list];
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item as T);
  return next;
}

export type RouteErrors = Record<string, string>;

export function validateRoutes(
  list: readonly RouteDraft[],
  channels: readonly Channel[],
): RouteErrors {
  const e: RouteErrors = {};
  if (list.length > MAX_ROUTES) e.routes = 'Use at most 100 routes.';
  list.forEach((r, i) => {
    if (!channels.some((c) => c.id === r.channelId))
      e[`routes[${i}].channel_id`] = 'Choose a channel.';
    const t = tagsError(r.tags);
    if (t) e[`routes[${i}].selector.tags`] = t;
  });
  return e;
}

export function routesPayload(list: readonly RouteDraft[]): RouteEntry[] {
  return list.map((r) => ({
    selector: { tags: [...r.tags], severity: [...r.severity], kinds: [...r.kinds] },
    channel_id: r.channelId,
    continue: r.cont,
  }));
}
