// SPDX-License-Identifier: AGPL-3.0-only

import {
  api,
  ApiRequestError,
  type ApiError,
  type Container,
  type Host,
  type ServerEvent,
} from './api/client';

export type LiveStatus = 'idle' | 'loading' | 'live' | 'reconnecting' | 'failed';

// "Problems first" (docs/06-ux.md): hosts that are down, then containers that are not healthy, sort to the top.
const HOST_RANK: Record<string, number> = { offline: 0, online: 1, gone: 2 };
const CONTAINER_RANK: Record<string, number> = {
  dead: 0,
  restarting: 0,
  exited: 1,
  paused: 2,
  created: 3,
  running: 4,
};

const hostRank = (h: Host): number => HOST_RANK[h.status] ?? 1;
const containerRank = (c: Container): number => CONTAINER_RANK[c.state] ?? 3;

function byRankThenName<T>(rank: (t: T) => number, name: (t: T) => string) {
  return (a: T, b: T) => rank(a) - rank(b) || name(a).localeCompare(name(b));
}

const sortHosts = byRankThenName<Host>(hostRank, (h) => h.hostname);
const sortContainers = byRankThenName<Container>(containerRank, (c) => c.name);

/**
 * The browser's copy of the inventory: loaded over REST, then kept current from the
 * live event stream. Rows change in place and never move under the reader's cursor;
 * when a change would reorder the list, `pendingReorder` counts it for a "refresh order" bar.
 */
class InventoryStore {
  hosts = $state<Host[]>([]);
  containers = $state<Container[]>([]);
  status = $state<LiveStatus>('idle');
  loaded = $state(false);
  failure = $state<ApiError | null>(null);
  pendingReorder = $state(0);
  /** The latest host change in words, for a polite live region (docs/06-ux.md, Accessibility). */
  announcement = $state('');

  private close: (() => void) | null = null;
  private queued: ServerEvent[] | null = null;
  private generation = 0;

  /** Starts loading and listening. Safe to call again; it does nothing while running. */
  start(): void {
    if (this.close) return;
    this.status = 'loading';
    this.close = api.openEvents({
      onOpen: () => void this.reload(),
      onEvent: (e) => this.receive(e),
      onError: (fatal) => {
        this.status = fatal ? 'failed' : 'reconnecting';
      },
    });
  }

  stop(): void {
    this.close?.();
    this.close = null;
    this.generation++;
    this.queued = null;
    this.status = 'idle';
    this.loaded = false;
    this.hosts = [];
    this.containers = [];
    this.pendingReorder = 0;
  }

  /** Puts the lists back in problems-first order. */
  refreshOrder(): void {
    this.hosts = [...this.hosts].sort(sortHosts);
    this.containers = [...this.containers].sort(sortContainers);
    this.pendingReorder = 0;
  }

  /** Puts an item the server just returned (for example after a tag edit) into the lists. */
  replaceHost(host: Host): void {
    if (!this.host(host.id)) return;
    this.upsert(this.hosts, host, hostRank, (h) => (this.hosts = h));
  }

  replaceContainer(container: Container): void {
    if (!this.container(container.id)) return;
    this.upsert(this.containers, container, containerRank, (c) => (this.containers = c));
  }

  host(id: string): Host | undefined {
    return this.hosts.find((h) => h.id === id);
  }

  container(id: string): Container | undefined {
    return this.containers.find((c) => c.id === id);
  }

  containersOf(hostId: string): Container[] {
    return this.containers.filter((c) => c.host_id === hostId);
  }

  // Events that arrive while the lists load are applied afterwards, in order. Each event carries a whole
  // item, so replaying them over a list that already includes some of them ends in the same state.
  private async reload(): Promise<void> {
    const generation = ++this.generation;
    this.queued = [];
    this.status = 'loading';
    try {
      const [hosts, containers] = await Promise.all([api.hosts(), api.containers()]);
      if (generation !== this.generation) return;
      this.hosts = hosts.sort(sortHosts);
      this.containers = containers.sort(sortContainers);
      this.pendingReorder = 0;
      this.loaded = true;
      this.failure = null;
      const queued = this.queued;
      this.queued = null;
      for (const e of queued) this.apply(e);
      this.status = 'live';
    } catch (e) {
      if (generation !== this.generation) return;
      this.queued = null;
      this.failure = e instanceof ApiRequestError ? e.error : null;
      this.status = 'failed';
    }
  }

  private receive(e: ServerEvent): void {
    if (this.queued) this.queued.push(e);
    else this.apply(e);
  }

  private apply(e: ServerEvent): void {
    switch (e.type) {
      case 'resync':
        void this.reload();
        return;
      case 'host.created':
      case 'host.updated':
        if (e.item) {
          const host = e.item as Host;
          this.announce(this.host(host.id), host);
          this.upsert(this.hosts, host, hostRank, (h) => (this.hosts = h));
        }
        return;
      case 'container.created':
      case 'container.updated':
        if (e.item)
          this.upsert(
            this.containers,
            e.item as Container,
            containerRank,
            (c) => (this.containers = c),
          );
        return;
      case 'container.removed':
        this.containers = this.containers.filter(
          (c) => c.id !== (e.item as Container | undefined)?.id,
        );
        return;
    }
  }

  private announce(before: Host | undefined, after: Host): void {
    if (!before && after.status === 'online') this.announcement = `${after.hostname} connected`;
    else if (before && before.status !== after.status)
      this.announcement = `${after.hostname} is now ${after.status}`;
  }

  private upsert<T extends { id: string }>(
    list: T[],
    item: T,
    rank: (t: T) => number,
    set: (l: T[]) => void,
  ): void {
    const i = list.findIndex((x) => x.id === item.id);
    if (i < 0) {
      set([...list, item]); // new rows go to the end until the reader asks for the order to be refreshed
      this.pendingReorder++;
      return;
    }
    const current = list[i];
    if (current && rank(current) !== rank(item)) this.pendingReorder++;
    const next = list.slice();
    next[i] = item;
    set(next);
  }
}

export const inventory = new InventoryStore();
