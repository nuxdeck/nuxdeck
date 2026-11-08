// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import axe from 'axe-core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import type { Incident, PublicStatus, StatusPage } from './lib/api/client';
import { router } from './lib/router.svelte';
import { move, SLUG_PATTERN, textProblem, validate, emptyForm } from './lib/statuspages/form';
import {
  ADMIN,
  SESSION,
  apiError,
  fakeServer,
  signedInRoutes,
  type Handler,
  type Reply,
} from './test-helpers';

const PAGE_ID = '01HZ0000000000000000000A01';
const INC_ID = '01HZ0000000000000000000B01';
const CHECK_A = '01HZ0000000000000000000C01';
const CHECK_B = '01HZ0000000000000000000C02';
const NOW = '2026-10-28T10:00:00Z';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

const VIEWER: Reply = { status: 200, body: { ...SESSION, user: { ...ADMIN, roles: ['viewer'] } } };

function pageDoc(extra: Partial<StatusPage> = {}): StatusPage {
  return {
    id: PAGE_ID,
    slug: 'acme',
    title: 'Acme status',
    description: 'Live status',
    published: true,
    components: [
      { id: 'k1', name: 'API', check_ids: [CHECK_A] },
      { id: 'k2', name: 'Web', check_ids: [] },
    ],
    created_at: NOW,
    updated_at: NOW,
    ...extra,
  };
}

function incident(extra: Partial<Incident> = {}): Incident {
  return {
    id: INC_ID,
    page_id: PAGE_ID,
    title: 'Slow API',
    body: 'We are looking.',
    status: 'investigating',
    impact: 'minor',
    created_by: 'u1',
    created_at: NOW,
    updated_at: NOW,
    resolved_at: null,
    updates: [{ status: 'investigating', body: 'We are looking.', created_by: 'u1', at: NOW }],
    ...extra,
  };
}

const days = Array.from({ length: 90 }, (_, i) => ({
  date: `d${i}`,
  status: i === 5 ? ('outage' as const) : ('operational' as const),
}));
const publicJson: PublicStatus = {
  title: 'Acme status',
  description: 'Live status',
  status: 'degraded',
  generated_at: NOW,
  components: [{ name: 'API', status: 'degraded', uptime_90d: 99.5, days }],
  incidents: [],
};

const checkRow = (id: string, name: string) => ({
  id,
  name,
  type: 'http',
  runner: 'server',
  status: { state: 'up' },
});

const listPage = (items: unknown[]): Reply => ({ status: 200, body: { items, next_cursor: null } });

function routes(extra: Record<string, Handler | Reply> = {}, me?: Reply) {
  return {
    ...signedInRoutes,
    ...(me ? { 'GET /api/v1/me': me } : {}),
    'GET /api/v1/status-pages': {
      status: 200,
      body: {
        items: [
          pageDoc(),
          pageDoc({ id: 'X2', slug: 'draft', title: 'Draft page', published: false }),
        ],
      },
    },
    'GET /api/v1/checks?limit=500': listPage([
      checkRow(CHECK_A, 'API health'),
      checkRow(CHECK_B, 'Web health'),
    ]),
    [`GET /api/v1/status-pages/${PAGE_ID}`]: {
      status: 200,
      body: pageDoc(),
      headers: { ETag: '"p3"' },
    },
    [`GET /api/v1/status-pages/${PAGE_ID}/incidents`]: {
      status: 200,
      body: { items: [incident()] },
    },
    'GET /status/acme.json': { status: 200, body: publicJson },
    ...extra,
  } as Record<string, Handler | Reply>;
}

async function open(): Promise<void> {
  router.navigate('/status-pages');
  render(App);
  await screen.findByRole('navigation', { name: 'Main' });
}

async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
  );
}

describe('status page list (STP-1)', () => {
  it('shows each page with its published state and public address, and copies the link', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    fakeServer(routes());
    await open();
    const table = await screen.findByRole('table', { name: 'Status pages' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(within(rows[0]!).getByText('Published')).toBeTruthy();
    expect(within(rows[0]!).getByText('/status/acme')).toBeTruthy();
    expect(within(rows[1]!).getByText('Draft')).toBeTruthy();
    await fireEvent.click(within(rows[0]!).getByRole('button', { name: /Copy link/ }));
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/status/acme`),
    );
    expect(screen.getByText('Copied the address of Acme status')).toBeTruthy();
  });

  it('shows an empty state, and a viewer gets no create button', async () => {
    fakeServer(routes({ 'GET /api/v1/status-pages': { status: 200, body: { items: [] } } }));
    await open();
    expect(await screen.findByText('No status pages yet')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'New status page' })).toBeTruthy();
    cleanup();
    fakeServer(
      routes({ 'GET /api/v1/status-pages': { status: 200, body: { items: [] } } }, VIEWER),
    );
    await open();
    await screen.findByText('No status pages yet');
    expect(screen.queryByRole('button', { name: 'New status page' })).toBeNull();
  });

  it('is accessible', async () => {
    fakeServer(routes());
    await open();
    await screen.findByRole('table', { name: 'Status pages' });
    expect(await violations(document.body)).toEqual([]);
  });
});

describe('status page editor (STP-1)', () => {
  it('creates a page with a component and its checks', async () => {
    const created = pageDoc({ components: [{ name: 'API', check_ids: [CHECK_B] }] });
    const calls = fakeServer(
      routes({
        'POST /api/v1/status-pages': { status: 201, body: created, headers: { ETag: '"p1"' } },
        [`GET /api/v1/status-pages/${PAGE_ID}/incidents`]: { status: 200, body: { items: [] } },
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: 'New status page' }));
    await screen.findByRole('heading', { name: 'New status page' });
    await fireEvent.input(screen.getByLabelText(/Address/), { target: { value: 'acme' } });
    await fireEvent.input(screen.getByLabelText(/^Title/), { target: { value: 'Acme status' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
    await fireEvent.input(screen.getByLabelText(/Component 1 name/), { target: { value: 'API' } });
    await fireEvent.click(screen.getByLabelText('Web health (http)'));
    await fireEvent.click(screen.getByRole('button', { name: 'Create status page' }));
    await screen.findByRole('heading', { name: 'Edit Acme status' });
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.body).toEqual({
      slug: 'acme',
      title: 'Acme status',
      description: '',
      published: false,
      components: [{ name: 'API', check_ids: [CHECK_B] }],
    });
    expect(post.headers['X-CSRF-Token']).toBeTruthy();
    // Creating hands over to editing: incidents and the preview appear.
    expect(screen.getByRole('heading', { name: 'Incidents' })).toBeTruthy();
  });

  it('validates the slug and title before sending anything', async () => {
    const calls = fakeServer(routes());
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: 'New status page' }));
    await fireEvent.input(await screen.findByLabelText(/Address/), {
      target: { value: 'Bad Slug' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Create status page' }));
    expect(await screen.findByText(/Use lowercase letters/)).toBeTruthy();
    expect(screen.getByText('This field is required.')).toBeTruthy();
    expect(document.activeElement?.id).toBe('sp-slug');
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('keeps the slug fixed when editing and sends If-Match', async () => {
    const calls = fakeServer(
      routes({
        [`PUT /api/v1/status-pages/${PAGE_ID}`]: {
          status: 200,
          body: pageDoc({ title: 'New title' }),
          headers: { ETag: '"p4"' },
        },
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    const slug = (await screen.findByLabelText(/Address/)) as HTMLInputElement;
    expect(slug.disabled).toBe(true);
    await fireEvent.input(document.getElementById('sp-title')!, { target: { value: 'New title' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['If-Match']).toBe('"p3"');
    expect((put.body as { slug: string }).slug).toBe('acme');
  });

  it('explains a stale version and offers a reload', async () => {
    fakeServer(
      routes({
        [`PUT /api/v1/status-pages/${PAGE_ID}`]: apiError(
          412,
          'API-PRE-001',
          'Item changed',
          'Reload the item and apply your change again.',
        ),
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByLabelText(/Address/);
    await fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('API-PRE-001');
    expect(screen.getByRole('button', { name: 'Reload latest version' })).toBeTruthy();
  });

  it('puts a server field error beside its field', async () => {
    fakeServer(
      routes({
        [`PUT /api/v1/status-pages/${PAGE_ID}`]: apiError(
          422,
          'API-VAL-001',
          'Invalid request',
          'Choose existing checks.',
          'components[0].check_ids',
        ),
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByLabelText(/Address/);
    await fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('Choose existing checks.')).toBeTruthy();
  });

  it('reorders and removes components with buttons, and announces it', async () => {
    fakeServer(routes());
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByLabelText(/^Component 1 name/);
    const names = () =>
      (screen.getAllByLabelText(/Component \d name/) as HTMLInputElement[]).map((i) => i.value);
    expect(names()).toEqual(['API', 'Web']);
    expect(
      (screen.getByRole('button', { name: 'Move API up' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    await fireEvent.click(screen.getByRole('button', { name: 'Move API down' }));
    expect(names()).toEqual(['Web', 'API']);
    expect(screen.getByText('API moved to position 2 of 2')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Remove Web' }));
    expect(names()).toEqual(['API']);
  });

  it('is read-only for a viewer', async () => {
    fakeServer(routes({}, VIEWER));
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /View Acme status/ }));
    await screen.findByLabelText(/Address/);
    expect(screen.getByText(/Only operators and admins can change it/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Save changes' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Add component' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Post incident' })).toBeNull();
    expect((document.getElementById('sp-title') as HTMLInputElement).disabled).toBe(true);
  });

  it('deletes after a confirmation', async () => {
    const calls = fakeServer(
      routes({ [`DELETE /api/v1/status-pages/${PAGE_ID}`]: { status: 204 } }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByLabelText(/Address/);
    await fireEvent.click(screen.getByRole('button', { name: 'Delete page' }));
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await fireEvent.click(screen.getByRole('button', { name: 'Delete status page' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE')).toBe(true));
    await screen.findByRole('table', { name: 'Status pages' });
  });

  it('is accessible, with components and incidents shown', async () => {
    fakeServer(routes());
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByText('Slow API');
    await screen.findByText(/uptime over the last 90 days/);
    expect(await violations(document.body)).toEqual([]);
  });
});

describe('incident composer and preview (STP-2)', () => {
  it('posts an incident, then resolves it', async () => {
    const posted = incident({ id: 'N1', title: 'DB down', body: 'Down.\nMore.' });
    const calls = fakeServer(
      routes({
        [`GET /api/v1/status-pages/${PAGE_ID}/incidents`]: { status: 200, body: { items: [] } },
        [`POST /api/v1/status-pages/${PAGE_ID}/incidents`]: { status: 201, body: posted },
        [`POST /api/v1/status-pages/${PAGE_ID}/incidents/N1/resolve`]: {
          status: 200,
          body: { ...posted, status: 'resolved', resolved_at: NOW },
        },
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByText('No incidents posted.');
    await fireEvent.input(document.getElementById('inc-title')!, {
      target: { value: 'DB down' },
    });
    await fireEvent.input(screen.getByLabelText(/What is happening/), {
      target: { value: 'Down.\nMore.' },
    });
    await fireEvent.change(screen.getByLabelText('Impact'), { target: { value: 'major' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Post incident' }));
    await screen.findByRole('heading', { name: 'DB down' });
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
      title: 'DB down',
      body: 'Down.\nMore.',
      status: 'investigating',
      impact: 'major',
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Resolve' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Resolve' })).toBeNull());
    expect(screen.getByText(/resolved/)).toBeTruthy();
  });

  it('refuses hidden characters and an empty body locally', async () => {
    const calls = fakeServer(
      routes({
        [`GET /api/v1/status-pages/${PAGE_ID}/incidents`]: { status: 200, body: { items: [] } },
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByText('No incidents posted.');
    await fireEvent.input(document.getElementById('inc-title')!, {
      target: { value: 'Bad' + String.fromCharCode(0x202e) },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Post incident' }));
    expect(await screen.findByText('Remove control and invisible characters.')).toBeTruthy();
    expect(screen.getByText('This field is required.')).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('adds an update to an incident', async () => {
    const next = incident({
      status: 'monitoring',
      updates: [
        ...incident().updates,
        { status: 'monitoring', body: 'Fix out.', created_by: 'u1', at: NOW },
      ],
    });
    const calls = fakeServer(
      routes({
        [`POST /api/v1/status-pages/${PAGE_ID}/incidents/${INC_ID}/updates`]: {
          status: 200,
          body: next,
        },
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    await screen.findByText('Slow API');
    await fireEvent.input(screen.getByLabelText('Update'), { target: { value: 'Fix out.' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add update' }));
    await screen.findByText('Fix out.');
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
      status: 'monitoring',
      body: 'Fix out.',
    });
  });

  it('renders the preview from the public endpoint, as text', async () => {
    const hostile: PublicStatus = {
      ...publicJson,
      title: '<script>alert(1)</script>',
      incidents: [
        {
          title: '<b>x</b>',
          body: 'a <i>b</i>',
          status: 'investigating',
          impact: 'minor',
          started_at: NOW,
          resolved_at: null,
          updates: [],
        },
      ],
    };
    const calls = fakeServer(routes({ 'GET /status/acme.json': { status: 200, body: hostile } }));
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    expect(await screen.findByText('<script>alert(1)</script>')).toBeTruthy();
    expect(screen.getByText('<b>x</b>')).toBeTruthy();
    expect(document.querySelector('main script, main b, main i')).toBeNull();
    expect(screen.getByText('99.5% uptime over the last 90 days')).toBeTruthy();
    expect(calls.some((c) => c.path === '/status/acme.json')).toBe(true);
  });

  it('says so when the page is not published', async () => {
    fakeServer(
      routes({
        [`GET /api/v1/status-pages/${PAGE_ID}`]: {
          status: 200,
          body: pageDoc({ published: false }),
          headers: { ETag: '"p3"' },
        },
      }),
    );
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /Edit Acme status/ }));
    expect(await screen.findByText('Publish the page to see its public preview.')).toBeTruthy();
  });
});

describe('form helpers', () => {
  it('mirrors the server slug rule', () => {
    for (const ok of ['a', 'acme-status', '0day']) expect(SLUG_PATTERN.test(ok)).toBe(true);
    for (const bad of ['', '-a', 'a-', 'A', 'a_b', 'a.b', 'a'.repeat(65)]) {
      expect(SLUG_PATTERN.test(bad)).toBe(false);
    }
  });

  it('flags control and invisible characters and long text', () => {
    expect(textProblem('ok', 10, true)).toBeUndefined();
    expect(textProblem('', 10, true)).toBeTruthy();
    expect(textProblem('a' + String.fromCharCode(0), 10, true)).toBeTruthy();
    expect(textProblem('a' + String.fromCharCode(0x200b), 10, true)).toBeTruthy();
    expect(textProblem('x'.repeat(11), 10, true)).toBeTruthy();
  });

  it('validates an empty form and moves items', () => {
    const e = validate(emptyForm(), true);
    expect(Object.keys(e).sort()).toEqual(['slug', 'title']);
    expect(move([1, 2, 3], 0, 2)).toEqual([2, 3, 1]);
    expect(move([1, 2, 3], 0, 5)).toEqual([1, 2, 3]);
  });
});

describe('the public page (STP-2, STP-3)', () => {
  // The Go test TestSTP2_GoldenHTML pins this exact markup, so the check here covers what nuxd serves.
  const html = readFileSync(
    join(
      process.cwd(),
      '..',
      'internal',
      'server',
      'statuspages',
      'testdata',
      'public.golden.html',
    ),
    'utf8',
  );

  it('has no axe violations and loads nothing but its own stylesheet', async () => {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    document.documentElement.innerHTML = doc.documentElement.innerHTML;
    document.documentElement.setAttribute('lang', doc.documentElement.getAttribute('lang') ?? '');
    expect(await violations(document.documentElement)).toEqual([]);
    expect(document.querySelector('script, iframe, img, [style]')).toBeNull();
    expect(document.querySelectorAll('link[rel="stylesheet"]')).toHaveLength(1);
    expect(document.querySelector('link[rel="stylesheet"]')?.getAttribute('href')).toBe(
      '/status/assets/status.css',
    );
    expect(document.querySelectorAll('h1')).toHaveLength(1);
    expect(document.title).toBe('Acme status');
  });
});
