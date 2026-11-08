// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const fake = vi.hoisted(() => {
  class FakePlot {
    static instances: FakePlot[] = [];
    cursor: { idx: number | null } = { idx: null };
    setData = vi.fn();
    setSize = vi.fn();
    destroyed = false;
    destroy = vi.fn(() => {
      this.destroyed = true;
    });
    constructor(
      public opts: Record<string, unknown>,
      public data: unknown[],
      public el: HTMLElement,
    ) {
      FakePlot.instances.push(this);
      const canvas = document.createElement('canvas');
      el.append(canvas);
    }
  }
  return { FakePlot };
});
vi.mock('uplot', () => ({ default: fake.FakePlot }));
vi.mock('uplot/dist/uPlot.min.css', () => ({}));

import App from './App.svelte';
import { api, type Host, type MetricsResult } from './lib/api/client';
import { router } from './lib/router.svelte';
import Chart from './lib/ui/Chart.svelte';
import RangePicker from './lib/ui/RangePicker.svelte';
import { FakeEventSource, fakeServer, signedInRoutes } from './test-helpers';

const { FakePlot } = fake;

class FakeResizeObserver {
  static instances: FakeResizeObserver[] = [];
  disconnected = false;
  constructor(public cb: () => void) {
    FakeResizeObserver.instances.push(this);
  }
  observe() {}
  unobserve() {}
  disconnect() {
    this.disconnected = true;
  }
}

beforeEach(() => {
  FakePlot.instances = [];
  FakeResizeObserver.instances = [];
  vi.stubGlobal('ResizeObserver', FakeResizeObserver);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

const base = {
  title: 'CPU usage',
  unit: 'percent' as const,
  from: 0,
  to: 120_000,
  syncKey: 'k',
  rangeLabel: 'last 1 hour',
  status: 'ready' as const,
  series: [
    {
      name: 'Total',
      points: [
        [0, 10],
        [60_000, 30],
        [120_000, 20],
      ] as [number, number][],
    },
  ],
};

const created = (n: number) => waitFor(() => expect(FakePlot.instances).toHaveLength(n));

async function axeViolations(el: HTMLElement): Promise<string[]> {
  const r = await axe.run(el, { rules: { 'color-contrast': { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join('; ')}`);
}

describe('Chart (MET-6)', () => {
  it('creates one plot with the shared crosshair key and a fixed time window', async () => {
    render(Chart, { props: base });
    await created(1);
    expect(FakePlot.instances).toHaveLength(1);
    const plot = FakePlot.instances[0]!;
    const opts = plot.opts as {
      cursor: { sync: { key: string } };
      legend: { show: boolean };
      scales: { x: { range: () => [number, number] } };
    };
    expect(opts.cursor.sync.key).toBe('k');
    expect(opts.legend.show).toBe(false);
    expect(opts.scales.x.range()).toEqual([0, 120]);
    expect(plot.data[0]).toEqual([0, 60, 120]);
  });

  it('updates data in place instead of rebuilding the plot', async () => {
    const view = render(Chart, { props: base });
    await created(1);
    await view.rerender({
      ...base,
      series: [{ name: 'Total', points: [[0, 99]] }],
    });
    expect(FakePlot.instances).toHaveLength(1);
    expect(FakePlot.instances[0]!.setData).toHaveBeenCalled();
  });

  it('rebuilds when the series change and destroys the old plot', async () => {
    const view = render(Chart, { props: base });
    await created(1);
    await view.rerender({ ...base, series: [{ name: 'Other', points: [[0, 1]] }] });
    await waitFor(() => expect(FakePlot.instances).toHaveLength(2));
    expect(FakePlot.instances[0]!.destroy).toHaveBeenCalledOnce();
    expect(FakePlot.instances[1]!.destroyed).toBe(false);
  });

  it('destroys the plot and disconnects the resize observer on unmount (no leaks)', async () => {
    const view = render(Chart, { props: base });
    await created(1);
    const plot = FakePlot.instances[0]!;
    view.unmount();
    expect(plot.destroy).toHaveBeenCalledOnce();
    expect(FakeResizeObserver.instances.every((o) => o.disconnected)).toBe(true);
  });

  it('resizes the plot when its container changes size', async () => {
    render(Chart, { props: base });
    await created(1);
    const plot = FakePlot.instances[0]!;
    Object.defineProperty(plot.el, 'clientWidth', { value: 500, configurable: true });
    FakeResizeObserver.instances.at(-1)!.cb();
    await waitFor(() => expect(plot.setSize).toHaveBeenCalledWith({ width: 500, height: 220 }));
  });

  it('shows loading, error and empty states without creating a plot', async () => {
    const loading = render(Chart, { props: { ...base, status: 'loading', series: [] } });
    expect(screen.getByRole('status').textContent).toContain('Loading');
    loading.unmount();

    const failed = render(Chart, {
      props: {
        ...base,
        status: 'error',
        series: [],
        error: { status: 422, code: 'API-VAL-001', message: 'Bad range.', hint: 'Pick another.' },
      },
    });
    expect(screen.getByRole('alert').textContent).toContain('Bad range.');
    expect(screen.getByRole('alert').textContent).toContain('Pick another.');
    failed.unmount();

    render(Chart, { props: { ...base, series: [{ name: 'Total', points: [] }] } });
    expect(screen.getByText('No data in this range.')).toBeTruthy();
    await new Promise((r) => setTimeout(r, 10));
    expect(FakePlot.instances).toHaveLength(0);
  });

  it('gives the chart an accessible name with the latest values, and a data table toggle', async () => {
    const { container } = render(Chart, { props: base });
    await created(1);
    const img = screen.getByRole('img');
    expect(img.getAttribute('aria-label')).toBe(
      'CPU usage, last 1 hour. Total: latest 20%, highest 30%',
    );
    const toggle = screen.getByRole('button', { name: 'Show data table' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByRole('table')).toBeNull();
    await fireEvent.click(toggle);
    const table = screen.getByRole('table', { name: /CPU usage/ });
    expect(within(table).getByRole('rowheader', { name: 'Total' })).toBeTruthy();
    expect(within(table).getByText('30%')).toBeTruthy();
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(await axeViolations(container)).toEqual([]);
  });
});

describe('RangePicker (MET-6)', () => {
  it('offers 1h, 6h, 24h, 7d and custom, and reports the choice', async () => {
    const onchange = vi.fn();
    render(RangePicker, { props: { value: { kind: 'preset', id: '24h' }, onchange } });
    const group = screen.getByRole('group', { name: 'Time range' });
    expect(
      within(group)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(['1h', '6h', '24h', '7d', 'Custom']);
    expect(screen.getByRole('button', { name: '24h' }).getAttribute('aria-pressed')).toBe('true');
    await fireEvent.click(screen.getByRole('button', { name: '6h' }));
    expect(onchange).toHaveBeenCalledWith({ kind: 'preset', id: '6h' });
  });

  it('moves between options with the arrow keys', async () => {
    render(RangePicker, { props: { value: { kind: 'preset', id: '1h' }, onchange: vi.fn() } });
    const first = screen.getByRole('button', { name: '1h' });
    first.focus();
    await fireEvent.keyDown(first.parentElement!, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '6h' }));
    await fireEvent.keyDown(first.parentElement!, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(first);
  });

  it('validates and applies a custom range', async () => {
    const onchange = vi.fn();
    render(RangePicker, { props: { value: { kind: 'preset', id: '1h' }, onchange } });
    await fireEvent.click(screen.getByRole('button', { name: 'Custom' }));
    const from = screen.getByLabelText('From') as HTMLInputElement;
    const to = screen.getByLabelText('To') as HTMLInputElement;
    await fireEvent.input(from, { target: { value: '2026-10-26T10:00' } });
    await fireEvent.input(to, { target: { value: '2026-10-26T09:00' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect((await screen.findByRole('alert')).textContent).toContain('after the start');
    expect(onchange).not.toHaveBeenCalled();
    expect(to.getAttribute('aria-invalid')).toBe('true');

    await fireEvent.input(from, { target: { value: '2026-10-26T08:00' } });
    await fireEvent.input(to, { target: { value: '2026-10-26T09:00' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect(onchange).toHaveBeenCalledWith({
      kind: 'custom',
      from: new Date('2026-10-26T08:00').getTime(),
      to: new Date('2026-10-26T09:00').getTime(),
    });
  });
});

const HOST_ID = '01HZ0000000000000000000001';
const host: Host = {
  id: HOST_ID,
  agent_id: '01HZ0000000000000000000009',
  hostname: 'alpha',
  os: 'linux',
  distro: 'Ubuntu',
  kernel: '7.0',
  arch: 'amd64',
  cpu_count: 4,
  memory_bytes: 1,
  facts: {},
  owner: '',
  tags: {},
  etag: '"e"',
  status: 'online',
  first_seen_at: '2026-10-25T10:00:00Z',
  last_seen_at: '2026-10-25T11:00:00Z',
  gone_at: null,
};

function metricsReply(url: URL): MetricsResult {
  const metric = url.searchParams.get('metric')!;
  const from = Number(url.searchParams.get('from'));
  const points: [number, number][] = Array.from({ length: 10 }, (_, i) => [from + i * 60_000, 0.4]);
  const labels: Record<string, string> = {};
  for (const l of url.searchParams.getAll('label')) {
    const [k, v] = l.split(':');
    labels[k!] = v!;
  }
  if (metric === 'nux_host_filesystem_bytes') labels.mount = '/';
  if (metric === 'nux_host_load_average') labels.window = '1m';
  if (metric.endsWith('_bytes_total')) labels.direction = 'rx';
  return {
    resolution: 'full',
    kind: 'gauge',
    unit: 'ratio',
    step_seconds: 60,
    from,
    to: Number(url.searchParams.get('to')),
    series: [{ metric, labels, points }],
  };
}

describe('Metrics tab on the host page', () => {
  async function openMetrics(fail = false) {
    fakeServer({
      ...signedInRoutes,
      'GET /api/v1/hosts?limit=500': { status: 200, body: { items: [host], next_cursor: null } },
    });
    const base = globalThis.fetch;
    const urls: URL[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const u = String(input);
        if (!u.startsWith('/api/v1/metrics/query?')) return base(input, init);
        const url = new URL(u, 'http://x');
        urls.push(url);
        if (fail && url.searchParams.get('metric') === 'nux_host_load_average') {
          return new Response(
            JSON.stringify({ error: { code: 'API-INT-001', message: 'Boom.', hint: 'Retry.' } }),
            { status: 500, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify(metricsReply(url)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );
    router.navigate(`/inventory/hosts/${HOST_ID}`);
    const view = render(App);
    await screen.findByRole('navigation', { name: 'Main' });
    FakeEventSource.current.open();
    await fireEvent.click(await screen.findByRole('tab', { name: 'Metrics' }));
    return { view, urls };
  }

  it('renders every host chart from one request set per chart, with a step derived from width', async () => {
    const { view, urls } = await openMetrics();
    await waitFor(() => expect(screen.getAllByRole('img').length).toBe(7));
    await created(7);
    const titles = screen
      .getAllByRole('figure')
      .map((f) => f.querySelector('figcaption')?.textContent);
    expect(titles).toEqual([
      'CPU usage',
      'Load average',
      'Memory and swap',
      'Disk usage per mount',
      'Disk I/O',
      'Network throughput',
      'Network errors',
    ]);
    const cpu = urls.find((u) => u.searchParams.get('metric') === 'nux_host_cpu_usage_ratio')!;
    expect(cpu.searchParams.get('target')).toBe(HOST_ID);
    expect(cpu.searchParams.getAll('label')).toEqual(['cpu:all']);
    const span = Number(cpu.searchParams.get('to')) - Number(cpu.searchParams.get('from'));
    expect(span).toBe(24 * 3_600_000);
    expect(Number(cpu.searchParams.get('step'))).toBeGreaterThan(60);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it('refetches with the new window when a preset is picked', async () => {
    const { urls } = await openMetrics();
    await waitFor(() => expect(screen.getAllByRole('img').length).toBe(7));
    urls.length = 0;
    await fireEvent.click(screen.getByRole('button', { name: '1h' }));
    await waitFor(() => expect(urls.length).toBeGreaterThan(0));
    const cpu = urls.find((u) => u.searchParams.get('metric') === 'nux_host_cpu_usage_ratio')!;
    expect(Number(cpu.searchParams.get('to')) - Number(cpu.searchParams.get('from'))).toBe(
      3_600_000,
    );
  });

  it('keeps the other charts when one fails', async () => {
    const { view } = await openMetrics(true);
    await waitFor(() => expect(screen.getAllByRole('img').length).toBe(6));
    expect(screen.getByRole('alert').textContent).toContain('Boom.');
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it('reaches the typed client with a label-limited query', async () => {
    fakeServer({
      'GET /api/v1/metrics/query?target=T&metric=m&from=1&to=2&step=5': {
        status: 200,
        body: { series: [] },
      },
    });
    await expect(
      api.metricsQuery({ target: 'T', metric: 'm', from: 1, to: 2, step: 5 }),
    ).resolves.toEqual({
      series: [],
    });
  });
});
