<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    api,
    ApiRequestError,
    type ApiError,
    type Check,
    type CheckResult,
    type CheckUptime,
  } from '../lib/api/client';
  import { canWriteChecks, runnerLabel } from '../lib/checks/access';
  import { checkTarget, describeErrorCode } from '../lib/checks/errors';
  import {
    buildResponseSeries,
    fetchResultsSince,
    formatLatency,
    formatUptime,
    recentResults,
  } from '../lib/checks/results';
  import { formatTime } from '../lib/format';
  import { inventory } from '../lib/inventory.svelte';
  import { PRESETS, describeRange, type PresetId } from '../lib/metrics/range';
  import type { ChartSeries } from '../lib/metrics/series';
  import { router } from '../lib/router.svelte';
  import Button from '../lib/ui/Button.svelte';
  import Chart from '../lib/ui/Chart.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import StatusBadge from '../lib/ui/StatusBadge.svelte';

  let { id }: { id: string } = $props();

  const REFRESH_MS = 30_000;
  const STRIP = 60;
  const canWrite = $derived(canWriteChecks());

  let check = $state<Check | null>(null);
  let missing = $state(false);
  let failure = $state<ApiError | null>(null);
  let uptime = $state<CheckUptime | null>(null);
  // Raw: hundreds of rows that are only read.
  let results = $state.raw<CheckResult[]>([]);
  let resultsStatus = $state<'loading' | 'ready' | 'error'>('loading');
  let resultsError = $state<ApiError | null>(null);
  let range = $state<PresetId>('24h');
  let now = $state(Date.now());

  let running = $state(false);
  let runMessage = $state('');
  let runError = $state<ApiError | null>(null);
  let cooling = $state(false);
  let confirming = $state(false);
  let deleting = $state(false);
  let deleteError = $state<ApiError | null>(null);
  let cooldownTimer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | null = null;

  const preset = $derived(PRESETS.find((p) => p.id === range) ?? PRESETS[2]!);
  const win = $derived({ from: now - preset.ms, to: now });
  const series = $derived<ChartSeries[]>(buildResponseSeries(results, win.from, win.to));
  const strip = $derived(recentResults(results, STRIP));
  const latest = $derived([...strip].reverse().slice(0, 10));
  const rangeLabel = $derived(describeRange({ kind: 'preset', id: range }));
  const code = $derived(check?.status.last_error_code ?? '');
  const codeInfo = $derived(code ? describeErrorCode(code) : null);

  $effect(() => {
    router.titleOverride = check?.name ?? null;
  });

  const apiError = (e: unknown): ApiError | null => (e instanceof ApiRequestError ? e.error : null);

  async function loadCheck(): Promise<void> {
    try {
      check = (await api.check(id)).check;
      failure = null;
    } catch (e) {
      const err = apiError(e);
      if (!err) throw e;
      if (err.status === 404) missing = true;
      else failure = err;
    }
  }

  async function loadUptime(): Promise<void> {
    try {
      uptime = await api.checkUptime(id);
    } catch {
      uptime = null;
    }
  }

  async function loadResults(): Promise<void> {
    controller?.abort();
    const mine = new AbortController();
    controller = mine;
    const from = Date.now() - preset.ms;
    try {
      const rows = await fetchResultsSince(id, from, mine.signal);
      if (mine.signal.aborted) return;
      results = rows;
      resultsStatus = 'ready';
      resultsError = null;
    } catch (e) {
      if (mine.signal.aborted) return;
      resultsError = apiError(e) ?? {
        status: 0,
        code: 'UI',
        message: 'Could not load the results.',
        hint: 'Try again.',
      };
      resultsStatus = 'error';
    }
  }

  async function refresh(): Promise<void> {
    now = Date.now();
    await Promise.all([loadCheck(), loadUptime(), loadResults()]);
  }

  onMount(() => {
    void refresh();
    const timer = setInterval(() => {
      if (!document.hidden) void refresh();
    }, REFRESH_MS);
    return () => clearInterval(timer);
  });

  onDestroy(() => {
    controller?.abort();
    clearTimeout(cooldownTimer);
  });

  function pick(next: PresetId): void {
    range = next;
    now = Date.now();
    resultsStatus = 'loading';
    void loadResults();
  }

  async function runNow(): Promise<void> {
    running = true;
    runError = null;
    runMessage = '';
    try {
      const r = await api.runCheck(id);
      runMessage =
        r.status === 'up'
          ? `Run finished: up in ${formatLatency(r.latency_ms)}.`
          : `Run finished: ${r.status}${r.error_code ? ` (${r.error_code})` : ''}${r.detail ? `. ${r.detail}` : '.'}`;
      await refresh();
    } catch (e) {
      const err = apiError(e);
      if (!err) throw e;
      runError = err;
      if (err.status === 429) {
        // Honour the server's wait so the button does not invite a second refusal.
        cooling = true;
        clearTimeout(cooldownTimer);
        cooldownTimer = setTimeout(() => (cooling = false), (err.retryAfter ?? 5) * 1000);
      }
    } finally {
      running = false;
    }
  }

  async function remove(): Promise<void> {
    deleting = true;
    deleteError = null;
    try {
      await api.deleteCheck(id);
      router.navigate('/checks');
    } catch (e) {
      const err = apiError(e);
      if (!err) throw e;
      deleteError = err;
      deleting = false;
    }
  }

  const uptimeRows = $derived([
    { key: '24h', label: '24 hours' },
    { key: '7d', label: '7 days' },
    { key: '30d', label: '30 days' },
    { key: '90d', label: '90 days' },
  ] as const);
</script>

{#if missing}
  <h1 id="page-title" tabindex="-1">Check not found</h1>
  <EmptyState title="Nothing here">
    This check does not exist, or it was deleted. Go back to the <a href="/checks">checks</a>.
  </EmptyState>
{:else if failure}
  <h1 id="page-title" tabindex="-1">Check</h1>
  <FormError error={failure} />
{:else if !check}
  <h1 id="page-title" tabindex="-1">Check</h1>
  <p role="status">Loading…</p>
{:else}
  <nav class="crumbs" aria-label="Breadcrumb"><a href="/checks">Checks</a> / {check.type}</nav>
  <div class="head">
    <h1 id="page-title" tabindex="-1">{check.name}</h1>
    <StatusBadge status={check.status.state} />
    {#if !check.enabled}<span class="muted">Paused</span>{/if}
  </div>

  {#if canWrite}
    <div class="actions">
      <Button onclick={runNow} disabled={running || cooling}>
        {running ? 'Running…' : 'Run now'}
      </Button>
      <a class="button-link secondary" href="/checks/{check.id}/edit">Edit</a>
      {#if !confirming}
        <Button variant="secondary" onclick={() => (confirming = true)}>Delete</Button>
      {/if}
    </div>
    {#if confirming}
      <div class="confirm" role="group" aria-label="Confirm delete">
        <p>
          Delete <strong>{check.name}</strong> and its history? This cannot be undone.
        </p>
        <div class="actions">
          <Button onclick={remove} disabled={deleting}>
            {deleting ? 'Deleting…' : 'Delete check'}
          </Button>
          <Button variant="secondary" onclick={() => (confirming = false)} disabled={deleting}
            >Cancel</Button
          >
        </div>
        {#if deleteError}<FormError error={deleteError} />{/if}
      </div>
    {/if}
  {/if}
  <p class="run-result" role="status">{runMessage}</p>
  {#if runError}
    <FormError error={runError} />
    {#if runError.status === 429 && runError.retryAfter !== undefined}
      <p class="muted">You can run it again in {runError.retryAfter} seconds.</p>
    {/if}
  {/if}

  <h2>Status</h2>
  <dl class="facts">
    <dt>Target</dt>
    <dd class="mono">{checkTarget(check)}</dd>
    <dt>Runs from</dt>
    <dd>{runnerLabel(check.runner, inventory.hosts)}</dd>
    <dt>Every</dt>
    <dd>
      {check.interval_s} s, timeout {check.timeout_s} s, {check.retries}
      {check.retries === 1 ? 'retry' : 'retries'}
    </dd>
    <dt>In this state since</dt>
    <dd>{formatTime(check.status.since)}</dd>
    <dt>Last checked</dt>
    <dd>{formatTime(check.status.last_checked)}</dd>
    <dt>Last latency</dt>
    <dd>{formatLatency(check.status.last_latency_ms)}</dd>
  </dl>

  {#if codeInfo}
    <section class="last-error" aria-labelledby="last-error-title">
      <h3 id="last-error-title">Last error: {codeInfo.title}</h3>
      <p class="mono">{code}</p>
      {#if check.status.last_detail}<p class="mono wrap">{check.status.last_detail}</p>{/if}
      <p>{codeInfo.hint}</p>
    </section>
  {/if}

  <h2>Uptime</h2>
  <dl class="uptime">
    {#each uptimeRows as u (u.key)}
      <div>
        <dt>{u.label}</dt>
        <dd class:nodata={uptime?.[u.key] == null}>{formatUptime(uptime?.[u.key])}</dd>
      </div>
    {/each}
  </dl>

  <h2>Response time</h2>
  <div class="range" role="group" aria-label="Time range">
    {#each PRESETS as p (p.id)}
      <button type="button" aria-pressed={range === p.id} onclick={() => pick(p.id)}>{p.id}</button>
    {/each}
  </div>
  <Chart
    title="Response time"
    unit="milliseconds"
    {series}
    status={resultsStatus}
    error={resultsError}
    from={win.from}
    to={win.to}
    syncKey="check-{id}"
    {rangeLabel}
  />

  <h2>Recent results</h2>
  {#if strip.length === 0}
    <p class="muted">No results yet. Use Run now, or wait for the next scheduled run.</p>
  {:else}
    <ol class="strip" aria-label="Last {strip.length} results, oldest first">
      {#each strip as r (r.ts)}
        <li class={r.status === 'up' ? 'up' : 'down'}>
          <span class="visually-hidden"
            >{r.status === 'up' ? 'Up' : 'Down'} at {formatTime(r.ts)}</span
          >
        </li>
      {/each}
    </ol>
    <div class="table-wrap">
      <table class="data-table">
        <caption class="visually-hidden">Latest results, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Result</th>
            <th scope="col">Time</th>
            <th scope="col" class="num">Latency</th>
            <th scope="col">Error</th>
          </tr>
        </thead>
        <tbody>
          {#each latest as r (r.ts)}
            <tr>
              <td><StatusBadge status={r.status === 'up' ? 'up' : 'down'} /></td>
              <td>{formatTime(r.ts)}</td>
              <td class="num">{formatLatency(r.latency_ms)}</td>
              <td class="mono wrap" title={r.detail}>{r.error_code || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .crumbs {
    margin-bottom: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
    overflow-wrap: anywhere;
  }

  h1:focus {
    outline: none;
  }

  h2 {
    margin: var(--space-6) 0 var(--space-2);
    font-size: var(--font-size-md);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    align-items: center;
  }

  .button-link.secondary {
    background: var(--color-surface);
    border-color: var(--color-border-strong);
    color: var(--color-text);
  }

  .confirm {
    display: grid;
    gap: var(--space-2);
    max-width: 40rem;
    margin-top: var(--space-3);
    padding: var(--space-3);
    border: 1px solid var(--color-status-critical);
    border-radius: var(--radius-1);
  }

  .run-result {
    margin: var(--space-3) 0 0;
    font-weight: 600;
  }

  .muted {
    color: var(--color-text-muted);
  }

  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2) var(--space-6);
    margin: 0;
  }

  dt {
    color: var(--color-text-muted);
    font-weight: 600;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .last-error {
    margin-top: var(--space-4);
    padding: var(--space-3);
    border: 1px solid var(--color-status-critical);
    border-radius: var(--radius-1);
    background: var(--color-status-critical-bg);
    display: grid;
    gap: var(--space-1);
    max-width: 48rem;
  }

  .last-error h3 {
    font-size: var(--font-size-md);
    color: var(--color-status-critical);
  }

  .last-error p {
    margin: 0;
  }

  .wrap {
    overflow-wrap: anywhere;
  }

  .uptime {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin: 0;
  }

  .uptime div {
    min-width: 8rem;
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
  }

  .uptime dd {
    font-size: var(--font-size-lg);
    font-weight: 700;
  }

  .uptime dd.nodata {
    color: var(--color-text-muted);
    font-size: var(--font-size-md);
    font-weight: 400;
  }

  .range {
    display: inline-flex;
    margin-bottom: var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    overflow: hidden;
  }

  .range button {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 0;
    background: var(--color-surface);
    color: var(--color-text);
    font-weight: 600;
    cursor: pointer;
  }

  .range button + button {
    border-left: 1px solid var(--color-border-strong);
  }

  .range button[aria-pressed='true'] {
    background: var(--color-accent);
    color: var(--color-accent-text);
  }

  .strip {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 1.75rem;
    margin: 0 0 var(--space-3);
    padding: 0;
    list-style: none;
  }

  /* Shape as well as colour: a failed run is a shorter bar (WCAG 1.4.1). */
  .strip li {
    flex: 1;
    max-width: 10px;
    border-radius: 1px;
  }

  .strip li.up {
    height: 100%;
    background: var(--color-status-healthy);
  }

  .strip li.down {
    height: 45%;
    background: var(--color-status-critical);
  }
</style>
