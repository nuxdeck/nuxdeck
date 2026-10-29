<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type ApiError, type Pressure, type PressureReport } from '../lib/api/client';
  import { inventory } from '../lib/inventory.svelte';
  import { formatPercent, levelOf, rankPressure } from '../lib/metrics/pressure';
  import { findSection } from '../lib/router.svelte';
  import Checklist from '../lib/onboarding/Checklist.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';

  const section = findSection('/');
  /** The ranking is a snapshot of the last few minutes, so a slow refresh is enough. */
  const REFRESH_MS = 15_000;

  let report = $state<PressureReport | null>(null);
  let failure = $state<ApiError | null>(null);
  let loading = $state(true);

  const hosts = $derived(rankPressure(report?.hosts ?? []));
  const containers = $derived(rankPressure(report?.containers ?? []));

  let inFlight: AbortController | null = null;

  async function refresh(): Promise<void> {
    inFlight?.abort();
    const controller = new AbortController();
    inFlight = controller;
    try {
      const next = await api.pressure(controller.signal);
      if (controller.signal.aborted) return;
      report = next;
      failure = null;
    } catch (e) {
      if (controller.signal.aborted) return;
      failure = (e as { error?: ApiError }).error ?? {
        status: 0,
        code: 'UI',
        message: 'Could not load the overview.',
        hint: 'Try again.',
      };
    } finally {
      if (inFlight === controller) loading = false;
    }
  }

  onMount(() => {
    void refresh();
    const timer = setInterval(() => {
      if (!document.hidden) void refresh();
    }, REFRESH_MS);
    return () => {
      clearInterval(timer);
      inFlight?.abort();
    };
  });

  const hostName = (id: string | undefined) =>
    (id ? inventory.host(id)?.hostname : undefined) ?? 'Unknown host';
</script>

<h1 id="page-title" tabindex="-1">{section?.title}</h1>
<p class="question">{section?.question}</p>

<Checklist />

{#if loading && !report}
  <p role="status">Loading…</p>
{:else if failure && !report}
  <div class="failure" role="alert">
    <strong>{failure.message}</strong>
    <span>{failure.hint}</span>
    <button type="button" onclick={() => void refresh()}>Try again</button>
  </div>
{:else if hosts.length === 0 && containers.length === 0}
  <EmptyState title="No hosts yet">
    Pressure by CPU, memory and disk appears here once a host is connected.
    <a href="/inventory/add">Add a host</a>
  </EmptyState>
{:else}
  {#if failure}
    <p class="stale" role="status">
      Showing the last result. The latest refresh failed: {failure.message}
    </p>
  {/if}
  <p class="hint">
    Worst first, by the highest of CPU, memory and disk over the last {Math.round(
      (report?.window_seconds ?? 300) / 60,
    )} minutes.
  </p>

  {@render grid('Hosts', 'No hosts to rank.', hosts, false)}
  {@render grid('Containers', 'No containers to rank.', containers, true)}
{/if}

{#snippet cell(percent: number | null, label: string)}
  {@const level = levelOf(percent)}
  <td class="num"
    ><span class="pill {level}" title={label}
      >{#if percent === null}<span class="none">no data</span>{:else}{formatPercent(
          percent,
        )}{/if}</span
    ></td
  >
{/snippet}

{#snippet grid(title: string, empty: string, rows: Pressure[], withHost: boolean)}
  <h2>{title} <span class="count">({rows.length})</span></h2>
  {#if rows.length === 0}
    <p class="count">{empty}</p>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <caption class="visually-hidden">{title} ranked by resource pressure, worst first</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            {#if withHost}<th scope="col">Host</th>{/if}
            <th scope="col" class="num">CPU</th>
            <th scope="col" class="num">Memory</th>
            <th scope="col" class="num">Disk</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as row (row.id)}
            <tr>
              <th scope="row">
                <a href="/inventory/{withHost ? 'containers' : 'hosts'}/{row.id}">{row.name}</a>
              </th>
              {#if withHost}
                <td><a href="/inventory/hosts/{row.host_id}">{hostName(row.host_id)}</a></td>
              {/if}
              {@render cell(row.cpu_percent, 'CPU')}
              {@render cell(row.memory_percent, 'Memory')}
              {@render cell(row.disk_percent, 'Disk')}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/snippet}

<style>
  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  h2 {
    margin: var(--space-6) 0 var(--space-2);
    font-size: var(--font-size-md);
  }

  .question {
    margin: var(--space-1) 0 var(--space-4);
    color: var(--color-text-muted);
  }

  .hint,
  .count,
  .stale {
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
    font-weight: 400;
  }

  .failure {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
  }

  .pill {
    display: inline-block;
    min-width: 6ch;
    padding: 0 var(--space-2);
    border-radius: var(--radius-1);
    font-weight: 600;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }

  .healthy {
    background: var(--color-status-healthy-bg);
    color: var(--color-status-healthy);
  }

  .warning {
    background: var(--color-status-warning-bg);
    color: var(--color-status-warning);
  }

  .critical {
    background: var(--color-status-critical-bg);
    color: var(--color-status-critical);
  }

  .none {
    color: var(--color-text-muted);
    font-weight: 400;
  }
</style>
