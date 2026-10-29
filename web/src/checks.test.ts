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
    destroy = vi.fn();
    constructor(
      public opts: Record<string, unknown>,
      public data: unknown[],
      el: HTMLElement,
    ) {
      FakePlot.instances.push(this);
      el.append(document.createElement('canvas'));
    }
  }
  return { FakePlot };
});
vi.mock('uplot', () => ({ default: fake.FakePlot }));
vi.mock('uplot/dist/uPlot.min.css', () => ({}));

import App from './App.svelte';
import type { Check } from './lib/api/client';
import { router } from './lib/router.svelte';
import {
  ADMIN,
  apiError,
  FakeEventSource,
  fakeServer,
  SESSION,
  signedInRoutes,
  type Call,
  type Handler,
  type Reply,
} from './test-helpers';

const { FakePlot } = fake;
const ID = '01HZ0000000000000000000777';
const ID2 = '01HZ0000000000000000000778';
const AGENT = '01HZ0000000000000000000999';

class FakeResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  FakePlot.instances = [];
  vi.stubGlobal('ResizeObserver', FakeResizeObserver);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

const NOW = '2026-10-28T10:00:00Z';

function check(id: string, name: string, extra: Partial<Check> = {}): Check {
  return {
    id,
    name,
    type: 'http',
    runner: 'server',
    interval_s: 60,
    timeout_s: 10,
    retries: 0,
    enabled: true,
    allow_private: false,
    http: { url: 'https://example.com/health', method: 'GET' },
    created_by: 'u1',
    updated_by: 'u1',
    created_at: NOW,
    updated_at: NOW,
    status: {
      state: 'up',
      since: NOW,
      last_checked: NOW,
      last_latency_ms: 42,
      last_error_code: '',
      last_detail: '',
    },
    ...extra,
  };
}

const page = (items: unknown[]): Reply => ({ status: 200, body: { items, next_cursor: null } });
const VIEWER = {
  status: 200,
  body: { ...SESSION, user: { ...ADMIN, roles: ['viewer'] } },
};
const uptimeOf = (v: Partial<Record<'24h' | '7d' | '30d' | '90d', number | null>>): Reply => ({
  status: 200,
  body: { '24h': null, '7d': null, '30d': null, '90d': null, ...v },
});

const base = (more: Record<string, Handler | Reply>) => ({ ...signedInRoutes, ...more });
const byId = (id: string) => document.getElementById(id) as HTMLInputElement;

async function open(path: string): Promise<void> {
  router.navigate(path);
  render(App);
  await screen.findByRole('navigation', { name: 'Main' });
}

const listRoutes = (items: Check[], me?: Reply) =>
  base({
    ...(me ? { 'GET /api/v1/me': me } : {}),
    'GET /api/v1/checks?limit=500': page(items),
    ...Object.fromEntries(
      items.map((c, i) => [
        `GET /api/v1/checks/${c.id}/uptime`,
        uptimeOf(i === 0 ? { '24h': 99.9 } : {}),
      ]),
    ),
  });

describe('checks list (UPT-5)', () => {
  it('lists checks problems first with text status, latency and uptime', async () => {
    const down = check(ID, 'Zeta API', {
      status: {
        state: 'down',
        since: NOW,
        last_checked: NOW,
        last_latency_ms: null,
        last_error_code: 'CHK-HTTP-001',
        last_detail: '',
      },
    });
    const unknown = check(ID2, 'Alpha', {
      status: {
        state: 'unknown',
        since: null,
        last_checked: null,
        last_latency_ms: null,
        last_error_code: '',
        last_detail: '',
      },
    });
    fakeServer(listRoutes([down, unknown, check('01HZ0000000000000000000779', 'Beta')]));
    await open('/checks');
    const table = await screen.findByRole('table', { name: 'Checks' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((r) => within(r).getByRole('link').textContent)).toEqual([
      'Zeta API',
      'Alpha',
      'Beta',
    ]);
    expect(within(rows[0]!).getByText('Down')).toBeTruthy();
    expect(within(rows[1]!).getByText('Unknown')).toBeTruthy();
    expect(within(rows[2]!).getByText('Up')).toBeTruthy();
    expect(within(rows[2]!).getByText('42 ms')).toBeTruthy();
    await waitFor(() => expect(within(rows[0]!).getByText('99.9%')).toBeTruthy());
    await waitFor(() => expect(within(rows[1]!).getByText('No data')).toBeTruthy());
  });

  it('filters by status', async () => {
    const down = check(ID, 'Broken', {
      status: { ...check(ID, 'x').status, state: 'down' },
    });
    fakeServer(listRoutes([down, check(ID2, 'Fine')]));
    await open('/checks');
    await screen.findByRole('table', { name: 'Checks' });
    await fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'down' } });
    const table = screen.getByRole('table', { name: 'Checks' });
    expect(within(table).queryByText('Fine')).toBeNull();
    expect(within(table).getByText('Broken')).toBeTruthy();
    await fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'unknown' } });
    expect(screen.getByText('No checks match')).toBeTruthy();
  });

  it('shows an empty state with a link to add a check, only for operators', async () => {
    fakeServer(listRoutes([]));
    await open('/checks');
    expect(await screen.findByText('No checks yet')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Add check' }).getAttribute('href')).toBe(
      '/checks/new',
    );
    cleanup();
    fakeServer(listRoutes([], VIEWER));
    await open('/checks');
    await screen.findByText('No checks yet');
    expect(screen.queryByRole('link', { name: 'Add check' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Add your first check' })).toBeNull();
  });
});

const detailRoutes = (c: Check, extra: Record<string, Handler | Reply> = {}, me?: Reply) =>
  base({
    ...(me ? { 'GET /api/v1/me': me } : {}),
    [`GET /api/v1/checks/${c.id}`]: { status: 200, body: c, headers: { ETag: '"c3"' } },
    [`GET /api/v1/checks/${c.id}/uptime`]: uptimeOf({ '24h': 100, '7d': 99.5 }),
    [`GET /api/v1/checks/${c.id}/results?limit=500`]: page([
      {
        ts: new Date(Date.now() - 60_000).toISOString(),
        status: 'up',
        latency_ms: 40,
        error_code: '',
        detail: '',
      },
      {
        ts: new Date(Date.now() - 120_000).toISOString(),
        status: 'down',
        latency_ms: 0,
        error_code: 'CHK-HTTP-001',
        detail: 'timeout',
      },
    ]),
    ...extra,
  });

describe('check detail (UPT-4)', () => {
  it('shows uptime windows with no data as text, the last error with its hint, and the chart', async () => {
    const c = check(ID, 'Public site', {
      status: {
        state: 'down',
        since: NOW,
        last_checked: NOW,
        last_latency_ms: null,
        last_error_code: 'CHK-HTTP-002',
        last_detail: 'status 503 <b>x</b>',
      },
    });
    fakeServer(detailRoutes(c));
    await open(`/checks/${ID}`);
    expect(await screen.findByRole('heading', { name: 'Public site' })).toBeTruthy();
    expect(screen.getAllByText('Down').length).toBeGreaterThan(0);
    expect(screen.getByText('100%')).toBeTruthy();
    expect(screen.getByText('99.5%')).toBeTruthy();
    expect(screen.getAllByText('No data')).toHaveLength(2);
    expect(screen.getByText(/Last error: Unexpected HTTP status/)).toBeTruthy();
    expect(screen.getByText(/Check the service, or adjust the expected status codes/)).toBeTruthy();
    // Server text is text, never markup.
    expect(screen.getByText('status 503 <b>x</b>')).toBeTruthy();
    expect(document.querySelector('main b')).toBeNull();
    await waitFor(() => expect(FakePlot.instances.length).toBeGreaterThan(0));
    const plot = FakePlot.instances.at(-1)!;
    expect((plot.data[1] as number[]).filter((v) => v !== null)).toEqual([40]);
    expect(screen.getByRole('group', { name: 'Time range' })).toBeTruthy();
  });

  it('renders an unknown check that has never run', async () => {
    const c = check(ID, 'New', {
      status: {
        state: 'unknown',
        since: null,
        last_checked: null,
        last_latency_ms: null,
        last_error_code: '',
        last_detail: '',
      },
    });
    fakeServer(detailRoutes(c, { [`GET /api/v1/checks/${ID}/results?limit=500`]: page([]) }));
    await open(`/checks/${ID}`);
    await screen.findByRole('heading', { name: 'New' });
    expect(screen.getByText('Unknown')).toBeTruthy();
    expect(screen.getByText(/No results yet/)).toBeTruthy();
    expect(screen.queryByText(/Last error/)).toBeNull();
  });

  it('runs now and reports the result', async () => {
    const calls = fakeServer(
      detailRoutes(check(ID, 'Site'), {
        [`POST /api/v1/checks/${ID}/run`]: {
          status: 200,
          body: { ts: NOW, status: 'up', latency_ms: 12, error_code: '', detail: '' },
        },
      }),
    );
    await open(`/checks/${ID}`);
    await fireEvent.click(await screen.findByRole('button', { name: 'Run now' }));
    expect(await screen.findByText('Run finished: up in 12 ms.')).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST' && c.path.endsWith('/run'))).toBe(true);
  });

  it('handles a 429 by showing the wait and disabling the button', async () => {
    fakeServer(
      detailRoutes(check(ID, 'Site'), {
        [`POST /api/v1/checks/${ID}/run`]: {
          ...apiError(429, 'CHK-RUN-004', 'Run requested too often.', 'Wait a few seconds.'),
          headers: { 'Retry-After': '5' },
        },
      }),
    );
    await open(`/checks/${ID}`);
    const button = await screen.findByRole('button', { name: 'Run now' });
    await fireEvent.click(button);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('CHK-RUN-004');
    expect(screen.getByText('You can run it again in 5 seconds.')).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Run now' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it('asks before deleting, then deletes and returns to the list', async () => {
    const calls = fakeServer({
      ...detailRoutes(check(ID, 'Site')),
      [`DELETE /api/v1/checks/${ID}`]: { status: 204 },
      'GET /api/v1/checks?limit=500': page([]),
    });
    await open(`/checks/${ID}`);
    await fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    const confirm = screen.getByRole('group', { name: 'Confirm delete' });
    await fireEvent.click(within(confirm).getByRole('button', { name: 'Delete check' }));
    await waitFor(() => expect(router.path).toBe('/checks'));
    expect(calls.find((c) => c.method === 'DELETE')!.headers['X-CSRF-Token']).toBe('csrf-token-1');
  });

  it('shows a viewer no write controls', async () => {
    fakeServer(detailRoutes(check(ID, 'Site'), {}, VIEWER));
    await open(`/checks/${ID}`);
    await screen.findByRole('heading', { name: 'Site' });
    for (const name of ['Run now', 'Delete']) {
      expect(screen.queryByRole('button', { name })).toBeNull();
    }
    expect(screen.queryByRole('link', { name: 'Edit' })).toBeNull();
  });

  it('says so when the check does not exist', async () => {
    fakeServer(
      base({
        [`GET /api/v1/checks/${ID}`]: apiError(404, 'API-NF-001', 'Not found.', 'Check the ID.'),
        [`GET /api/v1/checks/${ID}/uptime`]: apiError(404, 'API-NF-001', 'Not found.', 'x'),
        [`GET /api/v1/checks/${ID}/results?limit=500`]: apiError(
          404,
          'API-NF-001',
          'Not found.',
          'x',
        ),
      }),
    );
    await open(`/checks/${ID}`);
    expect(await screen.findByRole('heading', { name: 'Check not found' })).toBeTruthy();
  });
});

async function fill(label: string | RegExp, value: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText(label), { target: { value } });
}

describe('check editor: create (UPT-3)', () => {
  it('blocks an invalid form, focuses the first error and sends nothing', async () => {
    const calls = fakeServer(base({}));
    await open('/checks/new');
    await screen.findByRole('heading', { name: 'Add check' });
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    const name = byId('chk-name');
    await waitFor(() => expect(document.activeElement).toBe(name));
    expect(name.getAttribute('aria-invalid')).toBe('true');
    const described = name.getAttribute('aria-describedby')!;
    expect(document.getElementById(described)!.textContent).toContain('1 to 100 characters');
    expect(byId('chk-http-url').getAttribute('aria-invalid')).toBe('true');
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('switches fields per type and posts the matching section only', async () => {
    const calls = fakeServer(
      base({
        'POST /api/v1/checks': {
          status: 201,
          body: check(ID, 'Database', { type: 'tcp', http: undefined }),
          headers: { ETag: '"c1"' },
        },
        [`GET /api/v1/checks/${ID}`]: {
          status: 200,
          body: check(ID, 'Database', { type: 'tcp', http: undefined }),
        },
        [`GET /api/v1/checks/${ID}/uptime`]: uptimeOf({}),
        [`GET /api/v1/checks/${ID}/results?limit=500`]: page([]),
      }),
    );
    await open('/checks/new');
    await screen.findByRole('heading', { name: 'Add check' });
    await fireEvent.change(byId('chk-type'), { target: { value: 'tcp' } });
    expect(screen.queryByLabelText(/^URL/)).toBeNull();
    await fill(/^Name/, 'Database');
    await fill(/^Host/, 'db.internal');
    await fill(/^Port/, '5432');
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await waitFor(() => expect(router.path).toBe(`/checks/${ID}`));
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.body).toEqual({
      name: 'Database',
      type: 'tcp',
      runner: 'server',
      interval_s: 60,
      timeout_s: 10,
      retries: 0,
      enabled: true,
      allow_private: false,
      tcp: { host: 'db.internal', port: 5432 },
    });
  });

  it('sends a secret header and bearer token as strings, and never echoes them', async () => {
    const calls = fakeServer(
      base({
        'POST /api/v1/checks': apiError(422, 'API-VAL-001', 'Invalid.', 'Fix it.', 'name'),
      }),
    );
    await open('/checks/new');
    await screen.findByRole('heading', { name: 'Add check' });
    await fill(/^Name/, 'Api');
    await fill(/^URL/, 'https://api.example.com/v1');
    await fireEvent.click(screen.getByRole('button', { name: 'Add a header' }));
    await fill('Header 1 name', 'X-Api-Key');
    await fireEvent.click(screen.getByLabelText('Secret'));
    const secret = screen.getByLabelText('Header 1 secret value') as HTMLInputElement;
    expect(secret.type).toBe('password');
    expect(secret.placeholder).toBe('Not set');
    await fireEvent.input(secret, { target: { value: 'k-123' } });
    await fireEvent.change(byId('chk-http-auth-type'), { target: { value: 'bearer' } });
    await fireEvent.input(screen.getByLabelText('Token'), { target: { value: 'tok-9' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await screen.findByRole('alert');
    const body = calls.find((c) => c.method === 'POST')!.body as { http: unknown };
    expect(body.http).toMatchObject({
      headers: [{ name: 'X-Api-Key', secret: true, secret_value: 'k-123' }],
      auth: { type: 'bearer', token: 'tok-9' },
    });
    // A secret header never carries a plain value.
    expect(JSON.stringify(body)).not.toContain('"value"');
  });

  it('offers server and enrolled agents as runners', async () => {
    fakeServer(
      base({
        'GET /api/v1/hosts?limit=500': page([
          {
            id: ID2,
            agent_id: AGENT,
            hostname: 'web-1',
            os: 'linux',
            distro: '',
            kernel: '',
            arch: 'amd64',
            cpu_count: 1,
            memory_bytes: 1,
            facts: {},
            owner: '',
            tags: {},
            etag: '"h"',
            status: 'online',
            first_seen_at: NOW,
            last_seen_at: NOW,
            gone_at: null,
          },
        ]),
      }),
    );
    await open('/checks/new');
    await screen.findByRole('heading', { name: 'Add check' });
    FakeEventSource.current.open();
    await waitFor(() =>
      expect(screen.getByRole('option', { name: 'Agent on web-1' })).toBeTruthy(),
    );
    expect(
      (screen.getByRole('option', { name: 'Agent on web-1' }) as HTMLOptionElement).value,
    ).toBe(AGENT);
  });

  it('keeps allow_private and the other advanced options collapsed, with a warning', async () => {
    fakeServer(base({}));
    await open('/checks/new');
    await screen.findByRole('heading', { name: 'Add check' });
    const details = document.querySelector('details')!;
    expect(details.open).toBe(false);
    const toggle = screen.getByLabelText('Allow private and internal addresses');
    expect(document.getElementById(toggle.getAttribute('aria-describedby')!)!.textContent).toMatch(
      /private.*link-local/,
    );
  });

  it('shows a viewer no form', async () => {
    fakeServer(base({ 'GET /api/v1/me': VIEWER }));
    await open('/checks/new');
    expect(await screen.findByText('Operator access needed')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Save check' })).toBeNull();
  });
});

describe('check editor: edit (UPT-3)', () => {
  const stored = check(ID, 'Secured', {
    http: {
      url: 'https://example.com/',
      method: 'GET',
      headers: [{ name: 'X-Api-Key', secret: true, secret_value: { set: true } }],
      auth: { type: 'basic', username: 'ada', password: { set: true } },
    },
  });

  const editRoutes = (put: Handler | Reply, getReply?: Handler) =>
    base({
      [`GET /api/v1/checks/${ID}`]: getReply ?? {
        status: 200,
        body: stored,
        headers: { ETag: '"c3"' },
      },
      [`PUT /api/v1/checks/${ID}`]: put,
      [`GET /api/v1/checks/${ID}/uptime`]: uptimeOf({}),
      [`GET /api/v1/checks/${ID}/results?limit=500`]: page([]),
    });

  const saved = (call: Call): Reply => ({
    status: 200,
    body: stored,
    headers: { ETag: '"c4"' },
    ...(call ? {} : {}),
  });

  it('shows stored secrets as set, never as a value, and keeps them by omission', async () => {
    const calls = fakeServer(editRoutes(saved));
    await open(`/checks/${ID}/edit`);
    const header = (await screen.findByLabelText('Header 1 secret value')) as HTMLInputElement;
    expect(header.value).toBe('');
    expect(header.placeholder).toBe('Set — leave blank to keep');
    const password = screen.getByLabelText('Password') as HTMLInputElement;
    expect(password.value).toBe('');
    expect(password.placeholder).toBe('Set — leave blank to keep');
    expect(document.body.textContent).not.toMatch(/secret_value/);
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['If-Match']).toBe('"c3"');
    const http = (put.body as { http: { headers: unknown[]; auth: unknown } }).http;
    expect(http.headers).toEqual([{ name: 'X-Api-Key', secret: true }]);
    expect(http.auth).toEqual({ type: 'basic', username: 'ada' });
  });

  it('replaces one secret and clears another', async () => {
    const calls = fakeServer(editRoutes(saved));
    await open(`/checks/${ID}/edit`);
    await fireEvent.input(await screen.findByLabelText('Header 1 secret value'), {
      target: { value: 'rotated' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Clear stored Password' }));
    expect(screen.getByText('The stored value will be removed when you save.')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const http = (calls.find((c) => c.method === 'PUT')!.body as { http: unknown }).http;
    expect(http).toMatchObject({
      headers: [{ name: 'X-Api-Key', secret: true, secret_value: 'rotated' }],
      auth: { type: 'basic', username: 'ada', password: '' },
    });
  });

  it('reloads the latest version after a 412 and explains it', async () => {
    let reads = 0;
    fakeServer(
      editRoutes(
        apiError(412, 'API-PRE-001', 'The check changed.', 'Reload and try again.'),
        () => {
          reads++;
          return {
            status: 200,
            body: reads === 1 ? stored : { ...stored, name: 'Renamed elsewhere' },
            headers: { ETag: reads === 1 ? '"c3"' : '"c9"' },
          };
        },
      ),
    );
    await open(`/checks/${ID}/edit`);
    await screen.findByLabelText('Header 1 secret value');
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await waitFor(() => expect(screen.getByText(/changed while you were editing/)).toBeTruthy());
    expect(screen.getByRole('alert').textContent).toContain('API-PRE-001');
    await waitFor(() => expect(byId('chk-name').value).toBe('Renamed elsewhere'));
  });

  it('shows the server message for a missing If-Match (428)', async () => {
    fakeServer(
      editRoutes(apiError(428, 'API-PRE-002', 'If-Match is required.', 'Reload the check.')),
    );
    await open(`/checks/${ID}/edit`);
    await screen.findByLabelText('Header 1 secret value');
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('API-PRE-002');
    expect(alert.textContent).toContain('Reload the check.');
  });

  it('places a 422 field error on its input', async () => {
    fakeServer(
      editRoutes(
        apiError(
          422,
          'API-VAL-001',
          'The server may not check this address.',
          'Use an agent.',
          'http.url',
        ),
      ),
    );
    await open(`/checks/${ID}/edit`);
    await screen.findByLabelText('Header 1 secret value');
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await waitFor(() => expect(byId('chk-http-url').getAttribute('aria-invalid')).toBe('true'));
    const url = byId('chk-http-url');
    const err = document.getElementById(`${url.id}-error`)!;
    expect(url.getAttribute('aria-describedby')).toContain(err.id);
    expect(err.textContent).toBe('The server may not check this address.');
    await waitFor(() => expect(document.activeElement).toBe(url));
  });
});

describe('accessibility of the check screens (axe)', () => {
  async function violations(container: HTMLElement): Promise<string[]> {
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    return result.violations.map(
      (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
    );
  }

  it('has no violations on the list, the detail page and the editor', async () => {
    const c = check(ID, 'Site', {
      status: { ...check(ID, 'x').status, state: 'down', last_error_code: 'CHK-HTTP-001' },
    });
    fakeServer({
      ...listRoutes([c]),
      ...detailRoutes(c),
      [`GET /api/v1/checks/${ID}`]: { status: 200, body: c, headers: { ETag: '"c3"' } },
    });
    await open('/checks');
    await screen.findByRole('table', { name: 'Checks' });
    expect(await violations(document.body)).toEqual([]);

    router.navigate(`/checks/${ID}`);
    await screen.findByRole('heading', { name: 'Site' });
    await waitFor(() => expect(FakePlot.instances.length).toBeGreaterThan(0));
    expect(await violations(document.body)).toEqual([]);

    router.navigate(`/checks/${ID}/edit`);
    await screen.findByRole('button', { name: 'Save check' });
    await fireEvent.click(screen.getByRole('button', { name: 'Add a header' }));
    await fireEvent.change(byId('chk-http-auth-type'), { target: { value: 'basic' } });
    expect(await violations(document.body)).toEqual([]);
    await fireEvent.input(byId('chk-name'), { target: { value: '' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save check' }));
    await waitFor(() => expect(byId('chk-name').getAttribute('aria-invalid')).toBe('true'));
    expect(await violations(document.body)).toEqual([]);
  });
});
