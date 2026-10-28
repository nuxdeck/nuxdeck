<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Check } from '../lib/api/client';
  import { canWriteChecks, runnerLabel } from '../lib/checks/access';
  import { formatLatency, formatUptime } from '../lib/checks/results';
  import { formatTime } from '../lib/format';
  import { inventory } from '../lib/inventory.svelte';
  import { findSection } from '../lib/router.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import SelectField from '../lib/ui/SelectField.svelte';
  import StatusBadge from '../lib/ui/StatusBadge.svelte';

  const REFRESH_MS = 30_000;
  const UPTIME_BATCH = 6;
  // "Problems first" (docs/06-ux.md): down, then unknown, then up.
  const RANK: Record<string, number> = { down: 0, unknown: 1, up: 2 };

  const section = findSection('/checks');
  const canWrite = $derived(canWriteChecks());

  let items = $state<Check[]>([]);
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  // null: not fetched yet or unavailable; a nested null means the check has no runs in the window.
  let uptime = $state<Record<string, number | null | undefined>>({});
  let filter = $state('all');

  const filterOptions = [
    { value: 'all', label: 'All' },
    { value: 'down', label: 'Down' },
    { value: 'unknown', label: 'Unknown' },
    { value: 'up', label: 'Up' },
  ];

  const sorted = $derived(
    [...items].sort(
      (a, b) =>
        (RANK[a.status.state] ?? 1) - (RANK[b.status.state] ?? 1) || a.name.localeCompare(b.name),
    ),
  );
  const shown = $derived(
    filter === 'all' ? sorted : sorted.filter((c) => c.status.state === filter),
  );

  async function loadUptime(list: Check[]): Promise<void> {
    for (let i = 0; i < list.length; i += UPTIME_BATCH) {
      await Promise.all(
        list.slice(i, i + UPTIME_BATCH).map(async (c) => {
          try {
            // Await first: a spread evaluated before the await would drop results that landed meanwhile.
            const day = (await api.checkUptime(c.id))['24h'];
            uptime = { ...uptime, [c.id]: day };
          } catch {
            /* the cell keeps its dash; the check's own page shows the error */
          }
        }),
      );
    }
  }

  async function load(): Promise<void> {
    try {
      const list = await api.checks();
      items = list;
      failure = null;
      void loadUptime(list);
    } catch (e) {
      if (e instanceof ApiRequestError) failure = e.error;
      else throw e;
    } finally {
      loaded = true;
    }
  }

  onMount(() => {
    void load();
    const timer = setInterval(() => {
      if (!document.hidden) void load();
    }, REFRESH_MS);
    return () => clearInterval(timer);
  });
</script>

<div class="head">
  <div>
    <h1 id="page-title" tabindex="-1">{section?.title}</h1>
    <p class="question">{section?.question}</p>
  </div>
  {#if canWrite}<a class="button-link" href="/checks/new">Add check</a>{/if}
</div>

{#if failure}
  <FormError error={failure} />
{:else if !loaded}
  <p role="status">Loading…</p>
{:else if items.length === 0}
  <EmptyState title="No checks yet">
    Uptime checks watch an HTTP endpoint, a TCP port, a DNS record, a certificate or a host.
    {#if canWrite}<a href="/checks/new">Add your first check</a>.{:else}An operator can add one.{/if}
  </EmptyState>
{:else}
  <div class="toolbar">
    <SelectField id="check-filter" label="Show" bind:value={filter} options={filterOptions} />
    <p class="count" role="status">{shown.length} of {items.length} checks</p>
  </div>
  {#if shown.length === 0}
    <EmptyState title="No checks match">Choose a different status to see more.</EmptyState>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <caption class="visually-hidden">Checks</caption>
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col">Name</th>
            <th scope="col">Type</th>
            <th scope="col">Runs from</th>
            <th scope="col">Last checked</th>
            <th scope="col" class="num">Latency</th>
            <th scope="col" class="num">Uptime (24h)</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as c (c.id)}
            <tr>
              <td>
                <StatusBadge status={c.status.state} />
                {#if !c.enabled}<span class="muted"> (paused)</span>{/if}
              </td>
              <th scope="row" class="name"><a href="/checks/{c.id}">{c.name}</a></th>
              <td class="mono">{c.type}</td>
              <td>{runnerLabel(c.runner, inventory.hosts)}</td>
              <td>{formatTime(c.status.last_checked)}</td>
              <td class="num">{formatLatency(c.status.last_latency_ms)}</td>
              <td class="num">{uptime[c.id] !== undefined ? formatUptime(uptime[c.id]) : '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-6);
  }

  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  .question {
    margin: var(--space-1) 0 0;
    color: var(--color-text-muted);
  }

  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-4);
    margin-bottom: var(--space-3);
  }

  .count {
    margin: 0;
    padding-bottom: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .muted {
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .name {
    max-width: 28ch;
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
