// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { MAX_LABEL_FILTERS, metricsQueryString, type MetricsResult } from './lib/api/client';
import { formatPercent, levelOf, rankPressure } from './lib/metrics/pressure';
import {
  describeRange,
  parseCustomRange,
  resolveRange,
  stepFor,
  toLocalInput,
  widthBucket,
} from './lib/metrics/range';
import {
  alignSeries,
  describeStats,
  formatValue,
  mapValues,
  percentOf,
  summarize,
  sumByLabel,
  type ChartSeries,
} from './lib/metrics/series';
import { containerCharts, hostCharts } from './lib/metrics/sets';

const NOW = Date.UTC(2026, 9, 26, 12, 0, 0);

function result(series: { labels: Record<string, string>; points: [number, number][] }[]) {
  return {
    resolution: 'full',
    kind: 'gauge',
    unit: 'bytes',
    step_seconds: 15,
    from: 0,
    to: 0,
    series: series.map((s) => ({ metric: 'm', ...s })),
  } as MetricsResult;
}

describe('time range (MET-6)', () => {
  it.each([
    ['1h', 3_600_000],
    ['6h', 6 * 3_600_000],
    ['24h', 24 * 3_600_000],
    ['7d', 7 * 24 * 3_600_000],
  ] as const)('resolves the %s preset relative to now', (id, ms) => {
    expect(resolveRange({ kind: 'preset', id }, NOW)).toEqual({ from: NOW - ms, to: NOW });
  });

  it('keeps a custom range fixed', () => {
    expect(resolveRange({ kind: 'custom', from: 5, to: 9 }, NOW)).toEqual({ from: 5, to: 9 });
  });

  it('accepts a valid custom range in local time', () => {
    const r = parseCustomRange('2026-10-26T08:00', '2026-10-26T10:00', NOW);
    expect(r).toEqual({
      ok: true,
      range: {
        kind: 'custom',
        from: new Date('2026-10-26T08:00').getTime(),
        to: new Date('2026-10-26T10:00').getTime(),
      },
    });
  });

  it.each([
    ['', '2026-10-26T10:00', 'from', /start/],
    ['2026-10-26T08:00', '', 'to', /end/],
    ['2026-10-26T10:00', '2026-10-26T08:00', 'to', /after the start/],
    ['2026-10-26T08:00', '2026-10-26T08:00', 'to', /after the start/],
    ['2026-10-26T08:00', '2027-10-26T08:00', 'to', /future/],
    ['2026-10-26T09:59:30', '2026-10-26T10:00', 'to', /one minute/],
    ['2026-08-01T00:00', '2026-10-01T00:00', 'to', /31 days/],
  ] as const)('rejects %s .. %s', (from, to, field, message) => {
    const r = parseCustomRange(from, to, new Date('2026-10-26T12:00').getTime());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.field).toBe(field);
      expect(r.message).toMatch(message);
    }
  });

  it('round-trips a timestamp through the datetime-local format', () => {
    const ms = new Date('2026-10-26T09:05').getTime();
    expect(toLocalInput(ms)).toBe('2026-10-26T09:05');
  });

  it('describes the window', () => {
    expect(describeRange({ kind: 'preset', id: '6h' })).toBe('last 6 hours');
    expect(describeRange({ kind: 'custom', from: NOW - 1000, to: NOW })).toContain(' to ');
  });
});

describe('step selection', () => {
  const day = 24 * 3_600_000;

  it('asks for hundreds of points for 24h, not the 5,760 raw samples', () => {
    const step = stepFor(day, 800);
    expect(step).toBe(216);
    expect(day / 1000 / step).toBeLessThanOrEqual(400);
  });

  it('never goes below the 5 second floor and never above a day', () => {
    expect(stepFor(60_000, 2000)).toBe(5);
    expect(stepFor(400 * day, 100)).toBe(86_400);
  });

  it('clamps the point count for tiny and huge widths', () => {
    expect(stepFor(day, 10)).toBe(stepFor(day, 200));
    expect(stepFor(day, 99_999)).toBe(stepFor(day, 2400));
  });

  it('buckets widths so a resize does not refetch per pixel', () => {
    expect(widthBucket(801)).toBe(900);
    expect(widthBucket(850)).toBe(900);
    expect(widthBucket(10)).toBe(200);
  });
});

describe('query building', () => {
  const base = { target: '01HZ', metric: 'nux_host_cpu_usage_ratio', from: 1000.9, to: 2000 };

  it('writes target, metric, from and to as whole milliseconds', () => {
    expect(metricsQueryString(base)).toBe(
      'target=01HZ&metric=nux_host_cpu_usage_ratio&from=1000&to=2000',
    );
  });

  it('adds a whole-second step', () => {
    expect(metricsQueryString({ ...base, step: 215.2 })).toContain('&step=216');
    expect(metricsQueryString({ ...base, step: 0 })).toContain('&step=1');
  });

  it('encodes sorted label filters as name:value', () => {
    const q = metricsQueryString({ ...base, labels: { mode: 'iowait', cpu: 'all' } });
    expect(q.endsWith('&label=cpu%3Aall&label=mode%3Aiowait')).toBe(true);
  });

  it('escapes values that could break the query', () => {
    const q = metricsQueryString({ ...base, labels: { mount: '/a&b=c' } });
    expect(new URLSearchParams(q).getAll('label')).toEqual(['mount:/a&b=c']);
  });

  it('refuses more than four filters before asking the server', () => {
    const labels = Object.fromEntries(
      Array.from({ length: MAX_LABEL_FILTERS + 1 }, (_, i) => [`l${i}`, 'v']),
    );
    expect(() => metricsQueryString({ ...base, labels })).toThrow(RangeError);
  });
});

describe('series helpers', () => {
  it('aligns series onto the union of timestamps with gaps as null, x in seconds', () => {
    const a: ChartSeries = {
      name: 'a',
      points: [
        [1000, 1],
        [3000, 3],
      ],
    };
    const b: ChartSeries = {
      name: 'b',
      points: [
        [2000, 20],
        [3000, 30],
      ],
    };
    expect(alignSeries([a, b])).toEqual([
      [1, 2, 3],
      [1, null, 3],
      [null, 20, 30],
    ]);
  });

  it('turns non-finite values into gaps and handles no series', () => {
    expect(alignSeries([{ name: 'a', points: [[1000, NaN]] }])).toEqual([[1], [null]]);
    expect(alignSeries([])).toEqual([[]]);
  });

  it('sums interfaces per direction and skips filtered ones', () => {
    const r = result([
      {
        labels: { interface: 'eth0', direction: 'rx' },
        points: [
          [1, 10],
          [2, 20],
        ],
      },
      { labels: { interface: 'eth1', direction: 'rx' }, points: [[1, 5]] },
      { labels: { interface: 'lo', direction: 'rx' }, points: [[1, 999]] },
      { labels: { interface: 'eth0', direction: 'tx' }, points: [[1, 1]] },
    ]);
    const out = sumByLabel(
      r,
      'direction',
      (d) => d.toUpperCase(),
      (l) => l.interface !== 'lo',
    );
    expect(out).toEqual([
      {
        name: 'RX',
        points: [
          [1, 15],
          [2, 20],
        ],
      },
      { name: 'TX', points: [[1, 1]] },
    ]);
  });

  it('computes percent used per mount on matching timestamps only', () => {
    const used = result([
      {
        labels: { mount: '/' },
        points: [
          [1, 50],
          [2, 60],
          [3, 70],
        ],
      },
    ]);
    const size = result([
      {
        labels: { mount: '/' },
        points: [
          [1, 200],
          [3, 0],
        ],
      },
    ]);
    expect(percentOf(used, size, 'mount')).toEqual([{ name: '/', points: [[1, 25]] }]);
    expect(percentOf(undefined, undefined, 'mount')).toEqual([]);
  });

  it('formats values by unit and shows missing values as no data', () => {
    expect(formatValue('percent', 4.26)).toBe('4.3%');
    expect(formatValue('percent', 42.4)).toBe('42%');
    expect(formatValue('bytes', 1536)).toBe('1.5 KiB');
    expect(formatValue('bytesPerSecond', 2048)).toBe('2 KiB/s');
    expect(formatValue('cores', 0.5)).toBe('0.50 cores');
    expect(formatValue('perSecond', 0)).toBe('0/s');
    expect(formatValue('number', null)).toBe('no data');
    expect(formatValue('number', Infinity)).toBe('no data');
  });

  it('summarises series for the data table and the accessible name', () => {
    const stats = summarize([
      {
        name: 'a',
        points: [
          [1, 2],
          [2, 6],
        ],
      },
      { name: 'empty', points: [] },
    ]);
    expect(stats[0]).toEqual({ name: 'a', latest: 6, min: 2, avg: 4, max: 6 });
    expect(stats[1]).toEqual({ name: 'empty', latest: null, min: null, avg: null, max: null });
    expect(describeStats('number', stats)).toBe('a: latest 6.00, highest 6.00');
    expect(describeStats('number', [stats[1]!])).toBe('No data in this range.');
  });

  it('maps values without touching timestamps', () => {
    expect(mapValues({ name: 'a', points: [[1, 0.5]] }, (v) => v * 100, 'b')).toEqual({
      name: 'b',
      points: [[1, 50]],
    });
  });
});

describe('chart sets (MET-6)', () => {
  it('covers the host charts the requirement lists', () => {
    expect(hostCharts(4).map((c) => c.id)).toEqual([
      'cpu',
      'load',
      'memory',
      'disk-usage',
      'disk-io',
      'network',
      'network-errors',
    ]);
  });

  it('covers the container charts the requirement lists', () => {
    expect(containerCharts().map((c) => c.id)).toEqual([
      'cpu',
      'memory',
      'network',
      'blkio',
      'restarts',
    ]);
  });

  it('keeps every query within the server limit of four label filters', () => {
    for (const d of [...hostCharts(1), ...containerCharts()]) {
      for (const q of d.queries) {
        expect(Object.keys(q.labels ?? {}).length).toBeLessThanOrEqual(MAX_LABEL_FILTERS);
      }
    }
  });

  it('builds host CPU as percent, normalising CPU-seconds rates by core count', () => {
    const cpu = hostCharts(4)[0]!;
    const out = cpu.build({
      usage: result([{ labels: {}, points: [[1, 0.25]] }]),
      iowait: result([{ labels: {}, points: [[1, 0.2]] }]),
      steal: result([]),
    });
    expect(out).toEqual([
      { name: 'Total', points: [[1, 25]] },
      { name: 'I/O wait', points: [[1, 5]] },
    ]);
  });

  it('omits the memory limit series when the container is unlimited', () => {
    const mem = containerCharts()[1]!;
    const out = mem.build({
      ws: result([{ labels: {}, points: [[1, 100]] }]),
      limit: result([]),
    });
    expect(out.map((s) => s.name)).toEqual(['Working set']);
  });
});

describe('render helper performance (MET-6: 24h well under 1s)', () => {
  it('aligns and summarises 24h of 15 s samples for several series quickly', () => {
    const n = 5760;
    const series: ChartSeries[] = Array.from({ length: 6 }, (_, s) => ({
      name: `s${s}`,
      points: Array.from(
        { length: n },
        (_, i) => [i * 15_000, Math.sin(i / 50) + s] as [number, number],
      ),
    }));
    const t0 = performance.now();
    const data = alignSeries(series);
    const stats = summarize(series);
    const elapsed = performance.now() - t0;
    expect(data[0]).toHaveLength(n);
    expect(data).toHaveLength(7);
    expect(stats).toHaveLength(6);
    expect(elapsed).toBeLessThan(150);
  });
});

describe('pressure helpers (MET-7)', () => {
  const row = (name: string, score: number | null) => ({
    id: name,
    name,
    cpu_percent: score,
    memory_percent: null,
    disk_percent: null,
    score,
    rank: {},
  });

  it('puts the worst first and rows with no data last, ties by name', () => {
    expect(
      rankPressure([row('b', null), row('c', 10), row('a', 10), row('d', 90)]).map((r) => r.name),
    ).toEqual(['d', 'a', 'c', 'b']);
  });

  it('formats percentages and levels, with null as no data', () => {
    expect(formatPercent(null)).toBe('no data');
    expect(formatPercent(5.64)).toBe('5.6%');
    expect(formatPercent(93.2)).toBe('93%');
    expect([null, 10, 75, 90].map(levelOf)).toEqual(['none', 'healthy', 'warning', 'critical']);
  });
});
