// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import type { Container, Host, SearchHit } from './lib/api/client';
import { inventory } from './lib/inventory.svelte';
import { palette } from './lib/palette.svelte';
import { router } from './lib/router.svelte';
import { groupByEnv, hasTag, tagOptions } from './lib/tags';
import {
  ADMIN,
  apiError,
  FakeEventSource,
  fakeServer,
  SESSION,
  signedInRoutes,
  type Handler,
  type Reply,
} from './test-helpers';

const ID = (n: number) => `01HZ${String(n).padStart(22, '0')}`;

const host = (n: number, name: string, extra: Partial<Host> = {}): Host => ({
  id: ID(n),
  agent_id: ID(900 + n),
  hostname: name,
  os: 'linux',
  distro: 'Ubuntu',
  kernel: '7.0',
  arch: 'amd64',
  cpu_count: 2,
  memory_bytes: 1 << 30,
  facts: { ips: '10.0.0.5' },
  owner: '',
  tags: {},
  etag: `"h${n}"`,
  status: 'online',
  first_seen_at: '2026-10-25T10:00:00Z',
  last_seen_at: '2026-10-25T11:00:00Z',
  gone_at: null,
  ...extra,
});

const ctr = (
  n: number,
  hostN: number,
  name: string,
  extra: Partial<Container> = {},
): Container => ({
  id: ID(100 + n),
  host_id: ID(hostN),
  runtime: 'docker',
  runtime_id: `rid${n}`,
  name,
  image: 'nginx',
  state: 'running',
  ports: [],
  labels: {},
  owner: '',
  tags: {},
  etag: `"c${n}"`,
  restart_count: 0,
  created_at: null,
  gone_at: null,
  ...extra,
});

const list = (items: unknown[]): Reply => ({ status: 200, body: { items, next_cursor: null } });

function serve(hosts: Host[], containers: Container[], more: Record<string, Handler | Reply> = {}) {
  return fakeServer({
    ...signedInRoutes,
    'GET /api/v1/hosts?limit=500': list(hosts),
    'GET /api/v1/containers?limit=500': list(containers),
    ...more,
  });
}

async function open(path: string): Promise<void> {
  router.navigate(path);
  render(App);
  await screen.findByRole('navigation', { name: 'Main' });
  FakeEventSource.current.open();
  await waitFor(() => expect(inventory.loaded).toBe(true));
}

const asViewer: Record<string, Reply> = {
  'GET /api/v1/me': { status: 200, body: { ...SESSION, user: { ...ADMIN, roles: ['viewer'] } } },
};

async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return result.violations.map((v) => `${v.id}: ${v.help}`);
}

beforeEach(() => window.localStorage.clear());

afterEach(() => {
  cleanup();
  palette.close();
  vi.unstubAllGlobals();
  router.navigate('/');
});

describe('tag helpers (INV-3, INV-4)', () => {
  it('selects, lists and groups by tag', () => {
    expect(hasTag({ env: 'production' }, 'env:production')).toBe(true);
    expect(hasTag({ env: 'production' }, 'env:staging')).toBe(false);
    expect(hasTag({ env: 'production' }, 'env')).toBe(true);
    expect(hasTag({}, 'env')).toBe(false);
    expect(tagOptions([{ env: 'b', a: '1' }, { env: 'b' }])).toEqual(['a:1', 'env:b']);
    const groups = groupByEnv(
      ['x', 'y', 'z', 'w'],
      (s) => ({ x: 'prod', y: '', z: 'dev', w: 'prod' })[s] ?? '',
    );
    expect(groups.map((g) => [g.env, g.items])).toEqual([
      ['dev', ['z']],
      ['prod', ['x', 'w']],
      ['', ['y']],
    ]);
  });
});

describe('inventory filter and grouping (INV-3, INV-4)', () => {
  const hosts = [
    host(1, 'web-1', { tags: { env: 'production', team: 'core' } }),
    host(2, 'web-2', { tags: { env: 'staging' } }),
    host(3, 'bare'),
  ];
  const containers = [ctr(1, 1, 'nginx'), ctr(2, 2, 'redis', { tags: { env: 'production' } })];

  it('filters by a chosen tag, and by tag text typed in the filter', async () => {
    serve(hosts, containers);
    await open('/inventory');
    const select = screen.getByLabelText('Tag');
    await fireEvent.change(select, { target: { value: 'env:production' } });
    const tables = screen.getAllByRole('table');
    expect(within(tables[0]!).queryByText('web-2')).toBeNull();
    expect(within(tables[0]!).getByText('web-1')).toBeTruthy();
    // containers inherit the environment of their host unless they have their own
    expect(within(tables[1]!).getByRole('link', { name: 'nginx' })).toBeTruthy();
    expect(within(tables[1]!).getByRole('link', { name: 'redis' })).toBeTruthy();

    await fireEvent.change(select, { target: { value: '' } });
    await fireEvent.input(screen.getByLabelText('Filter'), { target: { value: 'team:core' } });
    expect(within(screen.getAllByRole('table')[0]!).getByText('web-1')).toBeTruthy();
    expect(within(screen.getAllByRole('table')[0]!).queryByText('web-2')).toBeNull();
  });

  it('groups hosts by environment, with the unlabelled ones last', async () => {
    serve(hosts, containers);
    await open('/inventory');
    await fireEvent.click(screen.getByLabelText('Group by environment'));
    const heads = screen
      .getAllByRole('columnheader', { name: /\(\d+\)/ })
      .map((h) => h.textContent?.replace(/\s+/g, ' ').trim());
    expect(heads.slice(0, 3)).toEqual(['production (1)', 'staging (1)', 'No environment (1)']);
  });
});

describe('tag and owner editor (INV-3)', () => {
  const h = host(1, 'web-1', { tags: { env: 'staging' }, owner: 'ops' });

  it('hides the editor from viewers', async () => {
    serve([h], [], asViewer);
    await open(`/inventory/hosts/${h.id}`);
    expect(screen.getByText('env:staging')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Edit tags and owner' })).toBeNull();
  });

  it('saves tags then owner with the ETag, updating the page', async () => {
    const calls = serve([h], [], {
      [`PUT /api/v1/items/hosts/${h.id}/tags`]: () => ({
        status: 200,
        body: { ...h, tags: { env: 'production' }, etag: '"h1b"' },
      }),
      [`PUT /api/v1/items/hosts/${h.id}/owner`]: () => ({
        status: 200,
        body: { ...h, tags: { env: 'production' }, owner: 'platform', etag: '"h1c"' },
      }),
    });
    await open(`/inventory/hosts/${h.id}`);
    await fireEvent.click(screen.getByRole('button', { name: 'Edit tags and owner' }));
    await waitFor(() => expect(document.activeElement?.id).toBe('tag-key-0'));
    await fireEvent.input(screen.getByLabelText('Tag value 1'), {
      target: { value: 'production' },
    });
    await fireEvent.input(screen.getByLabelText('Owner'), { target: { value: 'platform' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await screen.findByRole('button', { name: 'Edit tags and owner' });

    const puts = calls.filter((c) => c.method === 'PUT');
    expect(puts.map((c) => c.path)).toEqual([
      `/api/v1/items/hosts/${h.id}/tags`,
      `/api/v1/items/hosts/${h.id}/owner`,
    ]);
    expect(puts[0]!.body).toEqual({ tags: { env: 'production' } });
    expect(puts[0]!.headers['If-Match']).toBe('"h1"');
    expect(puts[0]!.headers['X-CSRF-Token']).toBe('csrf-token-1');
    expect(puts[1]!.body).toEqual({ owner: 'platform' });
    expect(puts[1]!.headers['If-Match']).toBe('"h1b"'); // the second write uses the ETag the first returned
    expect(screen.getByText('env:production')).toBeTruthy();
    expect(screen.getByText('platform')).toBeTruthy();
  });

  it('validates rows before asking the server', async () => {
    serve([h], []);
    await open(`/inventory/hosts/${h.id}`);
    await fireEvent.click(screen.getByRole('button', { name: 'Edit tags and owner' }));
    await fireEvent.input(screen.getByLabelText('Tag value 1'), { target: { value: '' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Every tag needs a key and a value.',
    );
  });

  it('explains a conflict (412) and shows the latest version', async () => {
    const latest = { ...h, tags: { env: 'production' }, etag: '"h1z"' };
    serve([h], [], {
      [`PUT /api/v1/items/hosts/${h.id}/tags`]: apiError(
        412,
        'API-PRE-001',
        'Item changed',
        'Reload the item and apply your change again.',
      ),
      [`GET /api/v1/hosts/${h.id}`]: { status: 200, body: latest },
    });
    await open(`/inventory/hosts/${h.id}`);
    await fireEvent.click(screen.getByRole('button', { name: 'Edit tags and owner' }));
    await fireEvent.input(screen.getByLabelText('Tag value 1'), { target: { value: 'dev' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await screen.findByText('env:production');
    expect(screen.getByRole('status', { hidden: true })).toBeTruthy();
  });

  it('has no accessibility violations while editing', async () => {
    serve([h], []);
    await open(`/inventory/hosts/${h.id}`);
    await fireEvent.click(screen.getByRole('button', { name: 'Edit tags and owner' }));
    expect(await violations(document.body)).toEqual([]);
  });
});

const inDialog = () => within(screen.getByRole('dialog', { name: 'Command palette' }));

const paletteBox = async () =>
  within(await screen.findByRole('dialog', { name: 'Command palette' })).getByRole('combobox');

describe('command palette (INV-5)', () => {
  const hit = (
    type: 'host' | 'container',
    n: number,
    name: string,
    extra: Partial<SearchHit> = {},
  ): SearchHit => ({
    type,
    id: type === 'host' ? ID(n) : ID(100 + n),
    name,
    status: 'online',
    match: 'name',
    detail: name,
    ...extra,
  });
  const hits = [
    hit('host', 1, 'web-1'),
    hit('container', 1, 'web', { host: 'web-1', status: 'running' }),
  ];

  it('opens with Ctrl+K and Cmd+K as a labelled combobox, and closes with Escape returning focus', async () => {
    serve([host(1, 'web-1')], []);
    await open('/inventory');
    const trigger = screen.getByRole('button', { name: /Search/ });
    trigger.focus();
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const dialog = await screen.findByRole('dialog', { name: 'Command palette' });
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    const box = within(dialog).getByRole('combobox');
    await waitFor(() => expect(document.activeElement).toBe(box));
    expect(box.getAttribute('aria-controls')).toBe(within(dialog).getByRole('listbox').id);

    await fireEvent.keyDown(box, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(trigger);

    await fireEvent.keyDown(window, { key: 'K', metaKey: true });
    expect(await screen.findByRole('dialog')).toBeTruthy();
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true, shiftKey: true });
    expect(screen.getByRole('dialog')).toBeTruthy(); // other chords are left alone
  });

  it('searches as the reader types, moves with the arrows and opens the item on Enter', async () => {
    const calls = serve([host(1, 'web-1')], [], {
      'GET /api/v1/search?q=web': { status: 200, body: { items: hits } },
    });
    await open('/inventory');
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const box = await paletteBox();
    await fireEvent.input(box, { target: { value: 'web' } });
    const options = await waitFor(() =>
      expect(inDialog().getAllByRole('option').length).toBeGreaterThan(0),
    ).then(() => inDialog().getAllByRole('option'));
    expect(options).toHaveLength(2);
    expect(box.getAttribute('aria-activedescendant')).toBe(options[0]!.id);
    expect(options[0]!.getAttribute('aria-selected')).toBe('true');
    expect(inDialog().getByRole('status').textContent).toContain('2 results');

    await fireEvent.keyDown(box, { key: 'ArrowDown' });
    expect(box.getAttribute('aria-activedescendant')).toBe(options[1]!.id);
    await fireEvent.keyDown(box, { key: 'ArrowDown' }); // wraps
    expect(box.getAttribute('aria-activedescendant')).toBe(options[0]!.id);
    await fireEvent.keyDown(box, { key: 'ArrowUp' }); // wraps back
    await fireEvent.keyDown(box, { key: 'Enter' });

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(router.path).toBe(`/inventory/containers/${ID(101)}`);
    expect(calls.filter((c) => c.path.startsWith('/api/v1/search'))).toHaveLength(1); // one request per settled query
  });

  it('says so when nothing matches or search fails, and keeps focus inside the dialog', async () => {
    serve([host(1, 'web-1')], [], {
      'GET /api/v1/search?q=zzz': { status: 200, body: { items: [] } },
      'GET /api/v1/search?q=boom': apiError(500, 'API-INT-001', 'Internal error', 'Try again.'),
    });
    await open('/inventory');
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const box = await paletteBox();
    await fireEvent.input(box, { target: { value: 'zzz' } });
    await waitFor(() =>
      expect(inDialog().getByRole('status').textContent?.trim()).toBe('No results'),
    );
    expect(inDialog().queryByRole('option')).toBeNull();

    await fireEvent.input(box, { target: { value: 'boom' } });
    await waitFor(() =>
      expect(inDialog().getByRole('status').textContent).toContain('Search is unavailable'),
    );

    // Tab wraps between the field and the Close button instead of leaving the dialog.
    const close = inDialog().getByRole('button', { name: 'Close' });
    close.focus();
    await fireEvent.keyDown(close, { key: 'Tab' });
    expect(document.activeElement).toBe(box);
    await fireEvent.keyDown(box, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(close);
  });

  it('has no accessibility violations with results showing', async () => {
    serve([host(1, 'web-1')], [], {
      'GET /api/v1/search?q=web': { status: 200, body: { items: hits } },
    });
    await open('/inventory');
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await fireEvent.input(await paletteBox(), { target: { value: 'web' } });
    await waitFor(() => expect(inDialog().getAllByRole('option').length).toBeGreaterThan(0)).then(
      () => inDialog().getAllByRole('option'),
    );
    expect(await violations(document.body)).toEqual([]);
  });
});
