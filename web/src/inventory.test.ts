// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { linuxInstallCommand } from './lib/agentCommand';
import type { Container, Host } from './lib/api/client';
import { formatBytes, formatPort, parseDisks } from './lib/format';
import { inventory } from './lib/inventory.svelte';
import { resolveRoute, router } from './lib/router.svelte';
import {
  apiError,
  FakeEventSource,
  fakeServer,
  signedInRoutes,
  type Handler,
  type Reply,
} from './test-helpers';

const ID = (n: number) => `01HZ${String(n).padStart(22, '0')}`;

function host(
  n: number,
  name: string,
  status: Host['status'] = 'online',
  extra: Partial<Host> = {},
): Host {
  return {
    id: ID(n),
    agent_id: ID(900 + n),
    hostname: name,
    os: 'linux',
    distro: 'Ubuntu 26.04 LTS',
    kernel: '7.0.0-38-generic',
    arch: 'amd64',
    cpu_count: 8,
    memory_bytes: 17179869184,
    facts: {
      ips: '10.0.0.5',
      cpu_model: 'Test CPU',
      boot_time_unix: '1790000000',
      disks: JSON.stringify([{ mount: '/', fstype: 'ext4', total_bytes: 1003753218048 }]),
    },
    owner: '',
    tags: {},
    etag: '"h-etag"',
    status,
    first_seen_at: '2026-10-25T10:00:00Z',
    last_seen_at: '2026-10-25T11:00:00Z',
    gone_at: null,
    ...extra,
  };
}

function ctr(
  n: number,
  hostN: number,
  name: string,
  state = 'running',
  extra: Partial<Container> = {},
): Container {
  return {
    id: ID(100 + n),
    host_id: ID(hostN),
    runtime: 'docker',
    runtime_id: `rid${n}`,
    name,
    image: 'nginx:1.27',
    state,
    ports: [{ host_ip: '0.0.0.0', host_port: 8080, container_port: 80, protocol: 'tcp' }],
    labels: { app: name, password: '[redacted]' },
    owner: '',
    tags: {},
    etag: '"c-etag"',
    restart_count: 2,
    created_at: '2026-10-24T09:00:00Z',
    gone_at: null,
    ...extra,
  };
}

const list = (items: unknown[]): Reply => ({ status: 200, body: { items, next_cursor: null } });

function serve(hosts: Host[], containers: Container[], more: Record<string, Handler | Reply> = {}) {
  return fakeServer({
    ...signedInRoutes,
    'GET /api/v1/hosts?limit=500': list(hosts),
    'GET /api/v1/containers?limit=500': list(containers),
    ...more,
  });
}

/** Renders the app at a path and lets the live stream connect, as a browser would. */
async function open(path: string): Promise<void> {
  router.navigate(path);
  render(App);
  await screen.findByRole('navigation', { name: 'Main' });
  FakeEventSource.current.open();
  await waitFor(() => expect(inventory.loaded).toBe(true));
}

const emit = (type: string, item: unknown) =>
  FakeEventSource.current.emit(type, { at: '2026-10-25T12:00:00Z', item });

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

describe('routes', () => {
  it('resolves sections, the add-host screen and item pages', () => {
    expect(resolveRoute('/inventory')).toEqual({ kind: 'section', path: '/inventory' });
    expect(resolveRoute('/inventory/add')).toEqual({ kind: 'add-host' });
    expect(resolveRoute(`/inventory/hosts/${ID(1)}`)).toEqual({ kind: 'host', id: ID(1) });
    expect(resolveRoute(`/inventory/containers/${ID(1)}`)).toEqual({
      kind: 'container',
      id: ID(1),
    });
    for (const bad of [
      '/inventory/hosts/',
      '/inventory/hosts/abc',
      '/inventory/hosts/../x',
      `/inventory/hosts/${ID(1)}/x`,
      '/inventory/other/x',
      '/nope',
    ]) {
      expect(resolveRoute(bad).kind).toBe('not-found');
    }
  });
});

describe('formatting', () => {
  it('formats sizes, ports and disks', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(17179869184)).toBe('16 GiB');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(-1)).toBe('—');
    expect(
      formatPort({ host_ip: '0.0.0.0', host_port: 8080, container_port: 80, protocol: 'tcp' }),
    ).toBe('0.0.0.0:8080→80/tcp');
    expect(formatPort({ host_ip: '::', host_port: 53, container_port: 53, protocol: 'udp' })).toBe(
      '[::]:53→53/udp',
    );
    expect(parseDisks('not json')).toEqual([]);
    expect(parseDisks(undefined)).toEqual([]);
    expect(parseDisks('[{"mount":"/","fstype":"ext4","total_bytes":5},{"bad":1}]')).toEqual([
      { mount: '/', fstype: 'ext4', total: 5 },
    ]);
  });

  it('quotes the token so no character can be read as shell syntax (INS-4)', () => {
    expect(linuxInstallCommand('nuxtok1.abc.def')).toBe(
      "curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --agent --token 'nuxtok1.abc.def'",
    );
    expect(linuxInstallCommand("x'; rm -rf /; echo '")).toBe(
      "curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --agent --token 'x'\\''; rm -rf /; echo '\\'''",
    );
  });
});

describe('live inventory store (INV-1, INV-2)', () => {
  it('loads both lists once the stream is open, problems first', async () => {
    serve(
      [host(1, 'b-online'), host(2, 'a-offline', 'offline'), host(3, 'a-online')],
      [
        ctr(1, 1, 'web'),
        ctr(2, 1, 'broken', 'dead'),
        ctr(3, 1, 'job', 'exited'),
        ctr(4, 1, 'api', 'restarting'),
      ],
    );
    await open('/inventory');
    expect(inventory.hosts.map((h) => h.hostname)).toEqual(['a-offline', 'a-online', 'b-online']);
    expect(inventory.containers.map((c) => c.name)).toEqual(['api', 'broken', 'job', 'web']);
    expect(inventory.status).toBe('live');
    expect(FakeEventSource.current.url).toBe('/api/v1/events');
  });

  it('reads every page of a long list', async () => {
    fakeServer({
      ...signedInRoutes,
      'GET /api/v1/hosts?limit=500': {
        status: 200,
        body: { items: [host(1, 'one')], next_cursor: ID(1) },
      },
      [`GET /api/v1/hosts?limit=500&cursor=${ID(1)}`]: list([host(2, 'two')]),
    });
    await open('/inventory');
    expect(inventory.hosts.map((h) => h.hostname).sort()).toEqual(['one', 'two']);
  });

  it('changes rows in place and offers a refresh instead of moving them', async () => {
    serve([host(1, 'alpha'), host(2, 'beta')], [ctr(1, 1, 'web')]);
    await open('/inventory');

    emit('host.updated', host(1, 'alpha', 'offline'));
    await waitFor(() => expect(inventory.host(ID(1))?.status).toBe('offline'));
    expect(inventory.hosts.map((h) => h.hostname)).toEqual(['alpha', 'beta']); // alpha is offline but did not jump
    expect(inventory.pendingReorder).toBe(1);

    emit('host.created', host(3, 'gamma'));
    emit('container.created', ctr(2, 3, 'cache'));
    await waitFor(() => expect(inventory.containers).toHaveLength(2));
    expect(inventory.hosts.at(-1)?.hostname).toBe('gamma'); // new rows join the end
    expect(inventory.pendingReorder).toBe(3); // alpha's status, the new host and the new container

    emit('container.removed', ctr(1, 1, 'web', 'running', { gone_at: '2026-10-25T12:00:00Z' }));
    await waitFor(() => expect(inventory.containers.map((c) => c.name)).toEqual(['cache']));

    inventory.refreshOrder();
    expect(inventory.hosts.map((h) => h.hostname)).toEqual(['alpha', 'beta', 'gamma']);
    expect(inventory.pendingReorder).toBe(0);
  });

  it('keeps events that arrive during the load and applies them afterwards', async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    serve([host(1, 'alpha')], [], {
      'GET /api/v1/hosts?limit=500': async () => {
        await gate;
        return list([host(1, 'alpha')]);
      },
    });
    router.navigate('/inventory');
    render(App);
    await screen.findByRole('navigation', { name: 'Main' });
    FakeEventSource.current.open();
    emit('host.updated', host(1, 'alpha', 'offline')); // arrives while the list is still loading
    release();
    await waitFor(() => expect(inventory.loaded).toBe(true));
    expect(inventory.host(ID(1))?.status).toBe('offline');
  });

  it('reloads after a resync event and after a reconnect', async () => {
    const calls = serve([host(1, 'alpha')], []);
    await open('/inventory');
    const loads = () => calls.filter((c) => c.path === '/api/v1/hosts?limit=500').length;
    expect(loads()).toBe(1);

    emit('resync', {});
    await waitFor(() => expect(loads()).toBe(2));

    FakeEventSource.current.fail(false);
    await waitFor(() => expect(inventory.status).toBe('reconnecting'));
    FakeEventSource.current.open();
    await waitFor(() => expect(loads()).toBe(3));
    await waitFor(() => expect(inventory.status).toBe('live'));
  });

  it('reports a stream the browser gave up on, and a list that fails to load', async () => {
    serve([host(1, 'alpha')], []);
    await open('/inventory');
    FakeEventSource.current.fail(true);
    await waitFor(() => expect(inventory.status).toBe('failed'));
    cleanup();

    serve([], [], {
      'GET /api/v1/hosts?limit=500': apiError(
        500,
        'API-INT-001',
        'Something went wrong on the server.',
        'Try again.',
      ),
    });
    router.navigate('/inventory');
    render(App);
    await screen.findByRole('navigation', { name: 'Main' });
    FakeEventSource.current.open();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('API-INT-001');
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  });

  it('announces host changes politely', async () => {
    serve([host(1, 'alpha')], []);
    await open('/inventory');
    emit('host.updated', host(1, 'alpha', 'offline'));
    await waitFor(() => expect(inventory.announcement).toBe('alpha is now offline'));
    emit('host.created', host(2, 'beta'));
    await waitFor(() => expect(inventory.announcement).toBe('beta connected'));
    const live = screen.getAllByRole('status').find((el) => el.textContent === 'beta connected');
    expect(live).toBeTruthy();
  });
});

describe('inventory list', () => {
  it('shows hosts and containers with words as well as colours, and links to their pages', async () => {
    serve(
      [host(1, 'alpha', 'offline'), host(2, 'beta')],
      [ctr(1, 2, 'web'), ctr(2, 2, 'job', 'exited')],
    );
    await open('/inventory');

    const hosts = screen.getByRole('table', { name: 'Hosts, problems first' });
    const rows = within(hosts).getAllByRole('row').slice(1);
    expect(rows.map((r) => r.querySelector('th')?.textContent)).toEqual(['alpha', 'beta']);
    expect(within(rows[0] as HTMLElement).getByText('Offline')).toBeTruthy();
    expect(within(rows[1] as HTMLElement).getByText('Online')).toBeTruthy();
    expect(within(rows[1] as HTMLElement).getByText('1 / 2')).toBeTruthy(); // running / total containers

    const link = within(hosts).getByRole('link', { name: 'alpha' });
    expect(link.getAttribute('href')).toBe(`/inventory/hosts/${ID(1)}`);
    const containers = screen.getByRole('table', { name: 'Containers, problems first' });
    expect(within(containers).getByText('Exited')).toBeTruthy();
    expect(within(containers).getByRole('link', { name: 'web' }).getAttribute('href')).toBe(
      `/inventory/containers/${ID(101)}`,
    );
    expect(within(containers).getAllByRole('link', { name: 'beta' })).toHaveLength(2);
    expect(screen.getByText('Live')).toBeTruthy();
  });

  it('filters both tables as the reader types', async () => {
    serve(
      [host(1, 'alpha'), host(2, 'beta')],
      [ctr(1, 1, 'web'), ctr(2, 2, 'db', 'running', { image: 'postgres:17' })],
    );
    await open('/inventory');
    await fireEvent.input(screen.getByLabelText('Filter'), { target: { value: 'postgres' } });
    expect(screen.getByText('No host matches the filter.')).toBeTruthy();
    const containers = screen.getByRole('table', { name: 'Containers, problems first' });
    expect(within(containers).getAllByRole('row')).toHaveLength(2); // header and db
    await fireEvent.input(screen.getByLabelText('Filter'), { target: { value: '10.0.0.5' } });
    expect(
      within(screen.getByRole('table', { name: 'Hosts, problems first' })).getAllByRole('row'),
    ).toHaveLength(3);
  });

  it('shows "N items changed" and refreshes the order on request', async () => {
    serve([host(1, 'alpha'), host(2, 'beta')], []);
    await open('/inventory');
    emit('host.updated', host(2, 'beta', 'offline'));
    const bar = await screen.findByText(/1 item changed/);
    expect(bar).toBeTruthy();
    const order = () =>
      within(screen.getByRole('table', { name: 'Hosts, problems first' }))
        .getAllByRole('row')
        .slice(1)
        .map((r) => r.querySelector('th')?.textContent);
    expect(order()).toEqual(['alpha', 'beta']);
    await fireEvent.click(screen.getByRole('button', { name: 'Refresh order' }));
    expect(order()).toEqual(['beta', 'alpha']);
    expect(screen.queryByText(/changed\./)).toBeNull();
  });

  it('teaches the next step when there is nothing yet (INS-4)', async () => {
    serve([], []);
    await open('/inventory');
    expect(screen.getByRole('heading', { name: 'No hosts yet' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Add your first host' }).getAttribute('href')).toBe(
      '/inventory/add',
    );
  });

  it('keeps Inventory marked in the sidebar on its sub-pages', async () => {
    serve([host(1, 'alpha')], []);
    await open(`/inventory/hosts/${ID(1)}`);
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'Inventory' }).getAttribute('aria-current')).toBe(
      'true',
    );
  });
});

describe('add a host (INS-4, INV-1)', () => {
  const token = {
    id: ID(500),
    token: 'nuxtok1.aaa.bbb.ccc',
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  };

  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
  });

  it('shows nothing secret until a token is created, then the command and the wait', async () => {
    const calls = serve([host(1, 'existing')], [], {
      'POST /api/v1/agents/tokens': { status: 201, body: token },
    });
    await open('/inventory/add');
    expect(screen.queryByText(/nuxtok1/)).toBeNull();

    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    const code = await screen.findByText(/--agent --token/);
    expect(code.textContent).toBe(
      "curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --agent --token 'nuxtok1.aaa.bbb.ccc'",
    );
    expect(calls.find((c) => c.method === 'POST')?.path).toBe('/api/v1/agents/tokens');
    expect(screen.getByText('Waiting for the agent to connect…')).toBeTruthy();
    expect(screen.getByText(/Expires/)).toBeTruthy();

    await fireEvent.click(screen.getByRole('button', { name: /Copy command/ }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(code.textContent);
    expect(await screen.findByText('Copied to the clipboard.')).toBeTruthy();
  });

  it('says "Connected" the moment a new host arrives, but not for hosts that were already there', async () => {
    serve([host(1, 'existing')], [], {
      'POST /api/v1/agents/tokens': { status: 201, body: token },
    });
    await open('/inventory/add');
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    await screen.findByText('Waiting for the agent to connect…');

    emit('host.updated', host(1, 'existing', 'offline')); // not the agent we are waiting for
    emit('host.updated', host(1, 'existing'));
    expect(screen.queryByText(/Connected:/)).toBeNull();

    emit('host.created', host(7, 'web-07'));
    const connected = await screen.findByText(/Connected:/);
    expect(connected.textContent).toContain('web-07');
    expect(screen.getByRole('link', { name: 'Open web-07' }).getAttribute('href')).toBe(
      `/inventory/hosts/${ID(7)}`,
    );
  });

  it('explains an expired token and offers a new one', async () => {
    serve([], [], {
      'POST /api/v1/agents/tokens': {
        status: 201,
        body: { ...token, expires_at: new Date(Date.now() - 1000).toISOString() },
      },
    });
    await open('/inventory/add');
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText(/This token has expired/)).toBeTruthy();
    expect(screen.getByText('The token expired before an agent connected.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Create a new token' })).toBeTruthy();
  });

  it('shows the error code when the token cannot be created', async () => {
    serve([], [], {
      'POST /api/v1/agents/tokens': apiError(
        403,
        'AUTH-DENY-005',
        'Your role does not allow this action.',
        'Ask an administrator for the required role.',
      ),
    });
    await open('/inventory/add');
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('AUTH-DENY-005');
    expect(screen.queryByText(/--agent --token/)).toBeNull();
  });

  it('tells the reader when copying is blocked', async () => {
    serve([], [], { 'POST /api/v1/agents/tokens': { status: 201, body: token } });
    await open('/inventory/add');
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockRejectedValue(new Error('blocked')) },
      configurable: true,
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    await fireEvent.click(await screen.findByRole('button', { name: /Copy command/ }));
    expect(await screen.findByText(/Copying was blocked/)).toBeTruthy();
  });
});

describe('item pages', () => {
  it('shows a host with its facts, disks and containers, and names the tab', async () => {
    serve([host(1, 'alpha')], [ctr(1, 1, 'web'), ctr(2, 2, 'elsewhere')]);
    await open(`/inventory/hosts/${ID(1)}`);

    expect(screen.getByRole('heading', { level: 1, name: 'alpha' })).toBeTruthy();
    expect(document.title).toBe('alpha · Nux Deck');
    expect(screen.getByText('Online')).toBeTruthy();
    expect(screen.getByText('Ubuntu 26.04 LTS (amd64)')).toBeTruthy();
    expect(screen.getByText('16 GiB')).toBeTruthy();
    expect(screen.getByText('10.0.0.5')).toBeTruthy();
    expect(screen.getByText('935 GiB')).toBeTruthy(); // the disk
    const containers = screen.getByRole('table', { name: 'Containers on alpha' });
    expect(within(containers).getByRole('link', { name: 'web' })).toBeTruthy();
    expect(within(containers).queryByText('elsewhere')).toBeNull();
    expect(screen.getByText('Owner')).toBeTruthy();
    expect(screen.getByText('not set')).toBeTruthy();
  });

  it('moves between tabs with the arrow keys and says what is not built yet', async () => {
    serve([host(1, 'alpha')], []);
    await open(`/inventory/hosts/${ID(1)}`);
    const overview = screen.getByRole('tab', { name: 'Overview' });
    expect(overview.getAttribute('aria-selected')).toBe('true');
    expect(screen.getAllByRole('tab').map((t) => t.getAttribute('tabindex'))).toEqual([
      '0',
      '-1',
      '-1',
      '-1',
      '-1',
      '-1',
    ]);

    await fireEvent.keyDown(overview, { key: 'ArrowRight' });
    const metrics = screen.getByRole('tab', { name: 'Metrics' });
    expect(metrics.getAttribute('aria-selected')).toBe('true');
    expect(document.activeElement).toBe(metrics);
    expect(
      within(screen.getByRole('tabpanel')).getByRole('group', { name: 'Time range' }),
    ).toBeTruthy(); // the charts (NUX-22)

    await fireEvent.keyDown(metrics, { key: 'End' });
    expect(screen.getByRole('tab', { name: 'Activity' }).getAttribute('aria-selected')).toBe(
      'true',
    );
    await fireEvent.keyDown(screen.getByRole('tab', { name: 'Activity' }), { key: 'ArrowRight' }); // wraps
    expect(overview.getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tabpanel', { name: 'Overview' })).toBeTruthy();
  });

  it('follows live changes to the host it shows', async () => {
    serve([host(1, 'alpha')], []);
    await open(`/inventory/hosts/${ID(1)}`);
    emit('host.updated', host(1, 'alpha', 'offline'));
    expect(await screen.findByText('Offline')).toBeTruthy();
  });

  it('shows a container with its ports, labels and host', async () => {
    serve([host(1, 'alpha')], [ctr(1, 1, 'web')]);
    await open(`/inventory/containers/${ID(101)}`);
    expect(screen.getByRole('heading', { level: 1, name: 'web' })).toBeTruthy();
    expect(document.title).toBe('web · Nux Deck');
    expect(screen.getByRole('link', { name: 'alpha' }).getAttribute('href')).toBe(
      `/inventory/hosts/${ID(1)}`,
    );
    expect(screen.getByText('0.0.0.0:8080→80/tcp')).toBeTruthy();
    expect(screen.getByText('nginx:1.27')).toBeTruthy();
    const labels = screen.getByRole('table', { name: 'Labels' });
    expect(within(labels).getByText('[redacted]')).toBeTruthy();
    expect(screen.getByText(/redacted on the host/)).toBeTruthy();
  });

  it('fetches an item that is no longer in the live list, and says so when it does not exist', async () => {
    const goneHost = host(5, 'retired', 'gone', { gone_at: '2026-10-20T00:00:00Z' });
    serve([], [], {
      [`GET /api/v1/hosts/${ID(5)}`]: { status: 200, body: goneHost },
      [`GET /api/v1/hosts/${ID(6)}`]: apiError(
        404,
        'API-NF-001',
        'Resource not found.',
        'Check the URL.',
      ),
      [`GET /api/v1/containers/${ID(106)}`]: apiError(
        404,
        'API-NF-001',
        'Resource not found.',
        'Check the URL.',
      ),
    });
    await open(`/inventory/hosts/${ID(5)}`);
    expect(await screen.findByRole('heading', { level: 1, name: 'retired' })).toBeTruthy();
    expect(screen.getByText('Gone')).toBeTruthy();
    cleanup();

    serve([], [], {
      [`GET /api/v1/hosts/${ID(6)}`]: apiError(
        404,
        'API-NF-001',
        'Resource not found.',
        'Check the URL.',
      ),
    });
    await open(`/inventory/hosts/${ID(6)}`);
    expect(await screen.findByRole('heading', { level: 1, name: 'Host not found' })).toBeTruthy();
    cleanup();

    serve([], [], {
      [`GET /api/v1/containers/${ID(106)}`]: apiError(
        404,
        'API-NF-001',
        'Resource not found.',
        'Check the URL.',
      ),
    });
    await open(`/inventory/containers/${ID(106)}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Container not found' }),
    ).toBeTruthy();
  });

  it('treats a malformed ID as an unknown page without asking the server', async () => {
    const calls = serve([], []);
    router.navigate('/inventory/hosts/not-an-id');
    render(App);
    expect(await screen.findByRole('heading', { level: 1, name: 'Page not found' })).toBeTruthy();
    expect(calls.some((c) => c.path.includes('not-an-id'))).toBe(false);
  });
});

async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
  );
}

describe('accessibility (axe)', () => {
  const populated = () =>
    serve(
      [host(1, 'alpha', 'offline'), host(2, 'beta')],
      [ctr(1, 2, 'web'), ctr(2, 2, 'job', 'exited'), ctr(3, 2, 'old', 'dead')],
      {
        'POST /api/v1/agents/tokens': {
          status: 201,
          body: {
            id: ID(500),
            token: 'nuxtok1.a.b.c',
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          },
        },
      },
    );

  it.each([
    ['the inventory list', '/inventory'],
    ['a host', `/inventory/hosts/${ID(1)}`],
    ['a container', `/inventory/containers/${ID(101)}`],
  ])('has no violations on %s', async (_name, path) => {
    populated();
    await open(path);
    await screen.findByRole('heading', { level: 1 });
    expect(await violations(document.body)).toEqual([]);
  });

  it('has no violations on the add-host screen, before and after a token', async () => {
    populated();
    await open('/inventory/add');
    expect(await violations(document.body)).toEqual([]);
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    await screen.findByText(/--agent --token/);
    expect(await violations(document.body)).toEqual([]);
    emit('host.created', host(9, 'new-host'));
    await screen.findByText(/Connected:/);
    expect(await violations(document.body)).toEqual([]);
  });

  it('has no violations on the empty inventory, the reorder bar and the failure state', async () => {
    serve([], []);
    await open('/inventory');
    expect(await violations(document.body)).toEqual([]);
    cleanup();

    populated();
    await open('/inventory');
    emit('host.updated', host(2, 'beta', 'offline'));
    await screen.findByText(/changed\./);
    expect(await violations(document.body)).toEqual([]);
    cleanup();

    serve([], [], {
      'GET /api/v1/hosts?limit=500': apiError(
        500,
        'API-INT-001',
        'Something went wrong on the server.',
        'Try again.',
      ),
    });
    await open('/inventory').catch(() => undefined);
    await screen.findByRole('alert');
    expect(await violations(document.body)).toEqual([]);
  });
});
