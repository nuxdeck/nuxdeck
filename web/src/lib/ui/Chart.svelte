<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import type uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import type { ApiError } from '../api/client';
  import { loadUPlot } from '../metrics/uplot';
  import {
    alignSeries,
    describeStats,
    formatValue,
    hasData,
    summarize,
    type Aligned,
    type ChartSeries,
    type Unit,
  } from '../metrics/series';

  interface Props {
    title: string;
    unit: Unit;
    series: ChartSeries[];
    status: 'loading' | 'ready' | 'error';
    error?: ApiError | null;
    /** The window shown, in unix milliseconds; the x axis always spans it, so gaps look like gaps. */
    from: number;
    to: number;
    /** Charts that share a key share their crosshair. */
    syncKey: string;
    /** Describes the window for the accessible name, such as "last 6 hours". */
    rangeLabel: string;
    fixedMax?: number;
    height?: number;
  }

  let {
    title,
    unit,
    series,
    status,
    error = null,
    from,
    to,
    syncKey,
    rangeLabel,
    fixedMax,
    height = 220,
  }: Props = $props();

  const data = $derived<Aligned>(alignSeries(series));
  const populated = $derived(hasData(series));
  const active = $derived(status === 'ready' && populated);
  const stats = $derived(summarize(series));
  const summary = $derived(describeStats(unit, stats));
  const uid = $props.id();

  let host = $state<HTMLDivElement | null>(null);
  let hover = $state<number | null>(null);
  let showTable = $state(false);
  let themeVersion = $state(0);

  // The canvas takes resolved colours, not var(); redraw when the theme changes under it.
  onMount(() => {
    const bump = () => themeVersion++;
    const observer = new MutationObserver(bump);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
    const media =
      typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null;
    media?.addEventListener('change', bump);
    return () => {
      observer.disconnect();
      media?.removeEventListener('change', bump);
    };
  });

  function token(name: string, fallback = 'currentColor'): string {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
  }

  let plot: uPlot | null = null;
  let xwin: [number, number] = [0, 1];

  function options(width: number): uPlot.Options {
    const text = token('--color-text-muted');
    const grid = token('--color-border');
    const font = `12px ${token('--font-sans', 'sans-serif')}`;
    const axis = {
      stroke: text,
      font,
      grid: { stroke: grid, width: 1 },
      ticks: { stroke: grid, width: 1 },
    };
    return {
      width,
      height,
      legend: { show: false },
      padding: [8, 8, 0, 0],
      cursor: { sync: { key: syncKey }, drag: { x: false, y: false } },
      scales: {
        x: { time: true, range: () => xwin },
        y: {
          range: (_u, _min, max) => [0, fixedMax ?? Math.max(max * 1.1, 1e-6)],
        },
      },
      axes: [
        axis,
        { ...axis, size: 64, values: (_u, ticks) => ticks.map((v) => formatValue(unit, v)) },
      ],
      series: [
        {},
        ...series.map((s, i) => ({
          label: s.name,
          stroke: token(`--color-chart-${(i % 6) + 1}`),
          width: 1.5,
          spanGaps: false,
          points: { show: false },
        })),
      ],
      hooks: { setCursor: [(u) => (hover = u.cursor.idx ?? null)] },
    };
  }

  // Rebuilt only when the shape of the chart changes; new points go through setData below.
  const shape = $derived(
    JSON.stringify([series.map((s) => s.name), unit, fixedMax, syncKey, height, themeVersion]),
  );

  $effect(() => {
    void shape;
    if (!host || !active) return;
    const el = host;
    return untrack(() => {
      let cancelled = false;
      let frame = 0;
      let observer: ResizeObserver | null = null;
      let u: uPlot | null = null;
      void loadUPlot().then((UPlot) => {
        if (cancelled) return;
        xwin = [from / 1000, to / 1000];
        const created = new UPlot(options(el.clientWidth || 600), data, el);
        u = created;
        plot = created;
        if (typeof ResizeObserver === 'function') {
          observer = new ResizeObserver(() => {
            cancelAnimationFrame(frame);
            frame = requestAnimationFrame(() => {
              if (el.clientWidth > 0) created.setSize({ width: el.clientWidth, height });
            });
          });
          observer.observe(el);
        }
      });
      return () => {
        cancelled = true;
        cancelAnimationFrame(frame);
        observer?.disconnect();
        u?.destroy();
        if (plot === u) plot = null;
        hover = null;
      };
    });
  });

  $effect(() => {
    const next = data;
    const win: [number, number] = [from / 1000, to / 1000];
    untrack(() => {
      xwin = win;
      plot?.setData(next, true);
    });
  });

  const legendValue = (i: number): string => {
    const col = data[i + 1] as (number | null)[] | undefined;
    if (!col) return formatValue(unit, null);
    if (hover !== null) return formatValue(unit, col[hover]);
    const last = series[i]?.points.at(-1);
    return formatValue(unit, last ? last[1] : null);
  };
</script>

<figure class="chart" aria-labelledby="{uid}-title">
  <figcaption id="{uid}-title">{title}</figcaption>

  {#if status === 'loading'}
    <div class="state" role="status">Loading…</div>
  {:else if status === 'error'}
    <div class="state" role="alert">
      <strong>{error?.message ?? 'Could not load this chart.'}</strong>
      {#if error?.hint}<span>{error.hint}</span>{/if}
    </div>
  {:else if !populated}
    <div class="state" role="status">
      <strong>No data in this range.</strong>
      <span>Charts fill in once the agent has reported metrics for this period.</span>
    </div>
  {:else}
    <div
      class="plot"
      role="img"
      aria-label="{title}, {rangeLabel}. {summary}"
      bind:this={host}
    ></div>
    <ul class="legend">
      {#each series as s, i (s.name)}
        <li>
          <span class="swatch swatch-{(i % 6) + 1}" aria-hidden="true"></span>
          <span class="name">{s.name}</span>
          <span class="value">{legendValue(i)}</span>
        </li>
      {/each}
    </ul>
    <button
      type="button"
      class="toggle"
      aria-expanded={showTable}
      aria-controls="{uid}-table"
      onclick={() => (showTable = !showTable)}
    >
      {showTable ? 'Hide data table' : 'Show data table'}
    </button>
    <div id="{uid}-table" hidden={!showTable}>
      {#if showTable}
        <div class="table-wrap">
          <table class="data-table">
            <caption class="visually-hidden">{title}, {rangeLabel}</caption>
            <thead>
              <tr>
                <th scope="col">Series</th>
                <th scope="col" class="num">Latest</th>
                <th scope="col" class="num">Lowest</th>
                <th scope="col" class="num">Average</th>
                <th scope="col" class="num">Highest</th>
              </tr>
            </thead>
            <tbody>
              {#each stats as s (s.name)}
                <tr>
                  <th scope="row">{s.name}</th>
                  <td class="num">{formatValue(unit, s.latest)}</td>
                  <td class="num">{formatValue(unit, s.min)}</td>
                  <td class="num">{formatValue(unit, s.avg)}</td>
                  <td class="num">{formatValue(unit, s.max)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}
</figure>

<style>
  .chart {
    margin: 0;
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
    min-width: 0;
  }

  figcaption {
    margin-bottom: var(--space-2);
    font-size: var(--font-size-md);
    font-weight: 600;
  }

  .plot {
    min-width: 0;
    overflow: hidden;
  }

  .plot :global(.u-cursor-x),
  .plot :global(.u-cursor-y) {
    border-color: var(--color-border-strong);
  }

  .state {
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: var(--space-1);
    min-height: 120px;
    color: var(--color-text-muted);
  }

  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1) var(--space-4);
    margin: var(--space-2) 0;
    padding: 0;
    list-style: none;
    font-size: var(--font-size-sm);
  }

  .legend li {
    display: flex;
    align-items: center;
    gap: var(--space-1);
  }

  .value {
    font-variant-numeric: tabular-nums;
    font-weight: 600;
  }

  .swatch {
    width: 12px;
    height: 4px;
    border-radius: 2px;
    background: var(--color-text);
  }
  .swatch-1 {
    background: var(--color-chart-1);
  }
  .swatch-2 {
    background: var(--color-chart-2);
  }
  .swatch-3 {
    background: var(--color-chart-3);
  }
  .swatch-4 {
    background: var(--color-chart-4);
  }
  .swatch-5 {
    background: var(--color-chart-5);
  }
  .swatch-6 {
    background: var(--color-chart-6);
  }

  .toggle {
    min-height: var(--target-size);
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: none;
    color: var(--color-text);
    cursor: pointer;
  }

  .table-wrap {
    margin-top: var(--space-2);
  }
</style>
