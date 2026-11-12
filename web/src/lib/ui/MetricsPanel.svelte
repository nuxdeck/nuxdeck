<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import {
    api,
    ApiRequestError,
    type ApiError,
    type ItemKind,
    type MetricsResult,
  } from '../api/client';
  import {
    describeRange,
    resolveRange,
    stepFor,
    widthBucket,
    type RangeSelection,
  } from '../metrics/range';
  import { containerCharts, hostCharts, type ChartDef } from '../metrics/sets';
  import type { ChartSeries } from '../metrics/series';
  import Chart from './Chart.svelte';
  import RangePicker from './RangePicker.svelte';

  interface Props {
    kind: ItemKind;
    id: string;
    /** Hosts only: CPU-seconds counters are divided by it to give a percentage. */
    cpuCount?: number;
  }

  let { kind, id, cpuCount = 1 }: Props = $props();

  /** Presets slide forward on this interval; a custom range is fixed and never refreshes. */
  const REFRESH_MS = 30_000;

  interface ChartState {
    status: 'loading' | 'ready' | 'error';
    series: ChartSeries[];
    error: ApiError | null;
  }

  const defs = $derived<ChartDef[]>(kind === 'hosts' ? hostCharts(cpuCount) : containerCharts());
  let range = $state<RangeSelection>({ kind: 'preset', id: '24h' });
  let now = $state(Date.now());
  let width = $state(800);
  // Raw: the series hold thousands of points that must not be wrapped in reactive proxies.
  let states = $state.raw<Record<string, ChartState>>({});
  let box = $state<HTMLDivElement | null>(null);

  const win = $derived(resolveRange(range, now));
  const bucket = $derived(widthBucket(width));
  const step = $derived(stepFor(win.to - win.from, bucket));
  const rangeLabel = $derived(describeRange(range));
  const syncKey = $derived(`metrics-${id}`);

  onMount(() => {
    const observer =
      typeof ResizeObserver === 'function'
        ? new ResizeObserver(() => {
            if (box && box.clientWidth > 0) width = box.clientWidth;
          })
        : null;
    if (box) observer?.observe(box);
    const timer = setInterval(() => {
      if (range.kind === 'preset' && !document.hidden) now = Date.now();
    }, REFRESH_MS);
    return () => {
      observer?.disconnect();
      clearInterval(timer);
    };
  });

  const toApiError = (e: unknown): ApiError =>
    e instanceof ApiRequestError
      ? e.error
      : { status: 0, code: 'UI', message: 'Could not load this chart.', hint: 'Try again.' };

  async function loadChart(
    def: ChartDef,
    q: { from: number; to: number; step: number },
    signal: AbortSignal,
  ): Promise<ChartSeries[]> {
    const entries = await Promise.all(
      def.queries.map(async (spec) => {
        const result = await api.metricsQuery(
          { target: id, metric: spec.metric, labels: spec.labels, ...q },
          signal,
        );
        return [spec.key, result] as const;
      }),
    );
    return def.build(Object.fromEntries(entries) as Record<string, MetricsResult>);
  }

  // One request set per chart, so a failing chart does not blank the others. A new window or target
  // aborts what is still in flight; charts that already have data keep showing it while they reload.
  $effect(() => {
    const q = { from: win.from, to: win.to, step };
    const list = defs;
    const controller = new AbortController();
    untrack(() => {
      const next: Record<string, ChartState> = {};
      for (const d of list) {
        next[d.id] =
          states[d.id]?.status === 'ready'
            ? states[d.id]!
            : { status: 'loading', series: [], error: null };
      }
      states = next;
    });
    for (const def of list) {
      loadChart(def, q, controller.signal)
        .then((series) => {
          if (!controller.signal.aborted) {
            states = { ...states, [def.id]: { status: 'ready', series, error: null } };
          }
        })
        .catch((e) => {
          if (controller.signal.aborted) return;
          states = { ...states, [def.id]: { status: 'error', series: [], error: toApiError(e) } };
        });
    }
    return () => controller.abort();
  });
</script>

<div class="panel" bind:this={box}>
  <div class="toolbar">
    <RangePicker value={range} onchange={(next) => ((range = next), (now = Date.now()))} />
    <p class="hint">
      Showing the {rangeLabel}. Hover a chart to compare values at the same moment.
    </p>
  </div>
  <div class="grid">
    {#each defs as def (def.id)}
      {@const s = states[def.id] ?? { status: 'loading', series: [], error: null }}
      <Chart
        title={def.title}
        unit={def.unit}
        fixedMax={def.fixedMax}
        series={s.series}
        status={s.status}
        error={s.error}
        from={win.from}
        to={win.to}
        {syncKey}
        {rangeLabel}
      />
    {/each}
  </div>
</div>

<style>
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }

  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr));
    gap: var(--space-4);
  }
</style>
