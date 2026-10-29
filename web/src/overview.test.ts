// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Pressure, PressureReport } from './lib/api/client';
import Overview from './routes/Overview.svelte';
import { apiError, fakeServer, type Handler, type Reply } from './test-helpers';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const H1 = '01HZ00000000000000000000A1';
const H2 = '01HZ00000000000000000000A2';
const C1 = '01HZ00000000000000000000B1';

const row = (id: string, name: string, p: Partial<Pressure> = {}): Pressure => ({
  id,
  name,
  cpu_percent: null,
  memory_percent: null,
  disk_percent: null,
  score: null,
  rank: {},
  ...p,
});

const report = (r: Partial<PressureReport>): Reply => ({
  status: 200,
  body: { generated_at: 1, window_seconds: 300, hosts: [], containers: [], ...r },
});

const PATH = 'GET /api/v1/overview/pressure';

describe('overview pressure grid (MET-7)', () => {
  it('lists hosts and containers worst first, linking to their pages, with null as "no data"', async () => {
    fakeServer({
      [PATH]: report({
        hosts: [
          row(H2, 'beta', { cpu_percent: 12, memory_percent: 95, disk_percent: null, score: 95 }),
          row(H1, 'alpha', { cpu_percent: 40, memory_percent: 30, disk_percent: 80, score: 80 }),
          row('01HZ00000000000000000000A3', 'gamma'),
        ],
        containers: [
          row(C1, 'web', { host_id: H1, cpu_percent: 3.4, memory_percent: 50, score: 50 }),
        ],
      }),
    });
    const { container } = render(Overview);

    const hosts = await screen.findByRole('table', { name: /Hosts ranked/ });
    const names = within(hosts)
      .getAllByRole('rowheader')
      .map((h) => h.textContent?.trim());
    expect(names).toEqual(['beta', 'alpha', 'gamma']);
    expect(within(hosts).getByRole('link', { name: 'beta' }).getAttribute('href')).toBe(
      `/inventory/hosts/${H2}`,
    );
    const gamma = within(hosts).getByRole('row', { name: /gamma/ });
    expect(within(gamma).getAllByText('no data')).toHaveLength(3);
    const beta = within(hosts).getByRole('row', { name: /beta/ });
    expect(within(beta).getByText('95%')).toBeTruthy();
    expect(within(beta).getByText('no data')).toBeTruthy();

    const containers = screen.getByRole('table', { name: /Containers ranked/ });
    expect(within(containers).getByRole('link', { name: 'web' }).getAttribute('href')).toBe(
      `/inventory/containers/${C1}`,
    );
    expect(
      within(containers).getByRole('link', { name: 'Unknown host' }).getAttribute('href'),
    ).toBe(`/inventory/hosts/${H1}`);
    expect(within(containers).getByText('3.4%')).toBeTruthy();

    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });

  it('says so when there are no hosts, and links to adding one', async () => {
    fakeServer({ [PATH]: report({}) });
    const { container } = render(Overview);
    await screen.findByRole('region', { name: 'No hosts yet' });
    expect(screen.getByRole('link', { name: 'Add a host' }).getAttribute('href')).toBe(
      '/inventory/add',
    );
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });

  it('shows the API error with a retry that works', async () => {
    let calls = 0;
    const handler: Handler = () => {
      calls++;
      return calls === 1
        ? apiError(500, 'API-INT-001', 'Something went wrong on the server.', 'Try again.')
        : report({ hosts: [row(H1, 'alpha', { cpu_percent: 1, score: 1 })] });
    };
    fakeServer({ [PATH]: handler });
    render(Overview);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Something went wrong');
    await fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByRole('table', { name: /Hosts ranked/ });
  });

  it('refreshes on an interval and stops when the page is left', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const calls = fakeServer({ [PATH]: report({ hosts: [row(H1, 'alpha', { score: 1 })] }) });
    const { unmount } = render(Overview);
    await screen.findByRole('table', { name: /Hosts ranked/ });
    // The next-steps checklist makes its own requests; this test counts pressure refreshes only.
    const pressure = () => calls.filter((c) => c.method + ' ' + c.path === PATH).length;
    expect(pressure()).toBe(1);
    await vi.advanceTimersByTimeAsync(15_000);
    await waitFor(() => expect(pressure()).toBe(2));
    unmount();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(pressure()).toBe(2);
  });
});
