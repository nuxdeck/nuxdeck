// SPDX-License-Identifier: AGPL-3.0-only

import type uPlot from 'uplot';

let pending: Promise<typeof uPlot> | null = null;

/** Loads uPlot once, on first use, so pages without charts do not pay for the library. */
export function loadUPlot(): Promise<typeof uPlot> {
  pending ??= import('uplot').then((m) => m.default);
  pending.catch(() => (pending = null)); // allow a retry after a failed chunk load
  return pending;
}
