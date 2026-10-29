// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { auth } from './lib/auth.svelte';
import { router } from './lib/router.svelte';
import {
  anonymousRoutes,
  emptyList,
  fakeEvents,
  type Handler,
  type Reply,
  SESSION,
  signedInRoutes,
} from './test-helpers';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  // The auth store is a module singleton; a half-finished sign-in must not leak into the next test.
  auth.cancelPending();
  router.navigate('/');
});

async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
  );
}

/**
 * Like fakeServer, but matches on the path without its query string, so a screen can
 * request filtered lists. Unknown reads answer with an empty list; unknown writes fail the test.
 */
function stubByPath(routes: Record<string, Handler | Reply>): void {
  fakeEvents();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      const path = String(input);
      const bare = path.split('?')[0];
      const exact = routes[`${method} ${path}`];
      const byBare = routes[`${method} ${bare}`];
      const route: Handler | Reply | undefined =
        exact ?? byBare ?? (method === 'GET' ? emptyList : undefined);
      if (!route) throw new Error(`unexpected request: ${method} ${path}`);
      const call = {
        method,
        path,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
        headers: {},
      };
      const reply = typeof route === 'function' ? await route(call) : route;
      if (reply.status === 204) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'Content-Type': 'application/json', ...reply.headers },
      });
    }),
  );
}

const ulid = (n: number) => `01HZX0000000000000000000${String(n).padStart(2, '0')}`;

const admin = {
  ...signedInRoutes,
  'GET /api/v1/me': { status: 200, body: SESSION },
  'GET /api/v1/settings': {
    status: 200,
    body: {
      'telemetry.enabled': true,
      'telemetry.locked': false,
      'server.public_url': 'https://nux.example.com',
      'setup.completed': true,
    },
  },
  'GET /api/v1/telemetry/preview': {
    status: 200,
    body: { schema_version: 1, sent_at: '2026-10-01T00:00:00Z' },
  },
  'GET /api/v1/settings/oidc': {
    status: 200,
    body: {
      configured: true,
      issuer: 'https://sso.example.com',
      client_id: 'nux',
      client_secret_set: true,
      scopes: ['openid', 'email'],
      groups_claim: 'groups',
      allowed_domains: ['example.com'],
      auto_provision: false,
      link_existing: true,
      redirect_uri: 'https://nux.example.com/api/v1/auth/oidc/callback',
    },
  },
  'GET /api/v1/settings/security': { status: 200, body: { require_2fa: false } },
  'GET /api/v1/users': {
    status: 200,
    body: {
      users: [
        {
          id: ulid(1),
          email: 'ada@example.com',
          name: 'Ada Admin',
          role: 'admin',
          disabled: false,
          totp_enabled: true,
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    },
  },
  'GET /api/v1/me/tokens': {
    status: 200,
    body: {
      tokens: [
        {
          id: ulid(2),
          name: 'ci',
          bindings: [],
          created_at: '2026-01-01T00:00:00Z',
          expires_at: '2027-01-01T00:00:00Z',
          last_used_at: null,
        },
      ],
    },
  },
  'GET /api/v1/status-pages': {
    status: 200,
    body: {
      items: [
        {
          id: ulid(3),
          slug: 'public',
          title: 'Nux status',
          published: true,
          components: [],
        },
      ],
    },
  },
};

const auditEntry = {
  id: 7,
  ts: '2026-10-01T10:00:00Z',
  actor_type: 'user',
  actor_id: ulid(1),
  action: 'settings.update',
  target_type: 'setting',
  target_id: 'telemetry.enabled',
  ip: '203.0.113.5',
  result: 'success',
  details: { value: true },
  prev_hash: '',
  hash: 'a'.repeat(64),
};

describe('accessibility of interactive states (axe)', () => {
  it('Account: two-factor enrolment and a newly created token', async () => {
    stubByPath({
      ...admin,
      'GET /api/v1/me/sessions': { status: 200, body: { sessions: [] } },
      'GET /api/v1/me/security': {
        status: 200,
        body: { totp_enabled: false, recovery_codes_left: 0, require_2fa: false },
      },
      'POST /api/v1/me/totp/enrol': {
        status: 200,
        body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Nux' },
      },
      'POST /api/v1/me/tokens': {
        status: 201,
        body: {
          token: 'nxt_example',
          details: {
            id: ulid(4),
            name: 'deploy',
            bindings: [],
            created_at: '2026-10-01T00:00:00Z',
            expires_at: '2027-01-01T00:00:00Z',
            last_used_at: null,
          },
        },
      },
    });
    router.navigate('/account');
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Account' });
    await fireEvent.click(await screen.findByRole('button', { name: 'Set up two-factor' }));
    await screen.findByText('JBSWY3DPEHPK3PXP');
    expect(await violations(container)).toEqual([]);

    await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'deploy' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    await screen.findByText('nxt_example');
    expect(await violations(container)).toEqual([]);
  });

  it('Audit: the detail drawer is open', async () => {
    stubByPath({
      ...admin,
      'GET /api/v1/audit': { status: 200, body: { items: [auditEntry], next_cursor: 'c2' } },
      'GET /api/v1/audit/verify': { status: 200, body: { ok: true, checked: 1 } },
    });
    router.navigate('/audit');
    const { container } = render(App);
    const details = await screen.findByRole('button', { name: /Details of entry 7/ });
    await fireEvent.click(details);
    await screen.findByRole('complementary', { name: /Entry 7/ });
    expect(await violations(container)).toEqual([]);
    await fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() =>
      expect(screen.queryByRole('complementary', { name: /Entry 7/ })).toBeNull(),
    );
  });

  it('Settings: telemetry and single sign-on panels with data loaded', async () => {
    stubByPath(admin);
    router.navigate('/settings');
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Telemetry' });
    await screen.findByDisplayValue('https://sso.example.com');
    expect(await violations(container)).toEqual([]);
  });

  it('Users: the account list with a loaded user', async () => {
    stubByPath(admin);
    router.navigate('/settings/users');
    const { container } = render(App);
    await screen.findByText('ada@example.com');
    expect(await violations(container)).toEqual([]);
  });

  it('Status pages: the editor for a new page', async () => {
    stubByPath(admin);
    router.navigate('/status-pages');
    const { container } = render(App);
    await fireEvent.click(await screen.findByRole('button', { name: 'New status page' }));
    await screen.findByRole('heading', { level: 2 });
    expect(await violations(container)).toEqual([]);
  });

  it('Setup wizard: every step', async () => {
    stubByPath({
      ...admin,
      'GET /api/v1/settings': {
        status: 200,
        body: {
          'telemetry.enabled': false,
          'telemetry.locked': false,
          'server.public_url': '',
          'setup.completed': false,
        },
      },
      'PUT /api/v1/settings': { status: 200, body: {} },
    });
    router.navigate('/setup');
    const { container } = render(App);
    await screen.findByRole('heading', { name: /Set up Nux Deck/ });
    expect(await violations(container)).toEqual([]);
    for (const skip of ['Skip for now', 'Skip for now']) {
      await fireEvent.click(await screen.findByRole('button', { name: skip }));
      expect(await violations(container)).toEqual([]);
    }
  });

  it('Login: the two-factor step after a password', async () => {
    stubByPath({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': {
        status: 200,
        body: {
          pending: { ticket: 'tkt', expires_at: '2027-01-01T00:00:00Z', enrol_required: false },
        },
      },
    });
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Sign in to Nux Deck' });
    await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'a@example.com' } });
    await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'secret-pass' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByLabelText('Code');
    expect(await violations(container)).toEqual([]);
  });
  it('Login: the forced two-factor enrolment step', async () => {
    stubByPath({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': {
        status: 200,
        body: {
          pending: { ticket: 'tkt', expires_at: '2027-01-01T00:00:00Z', enrol_required: true },
        },
      },
      'POST /api/v1/auth/totp/enrol': {
        status: 200,
        body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Nux' },
      },
    });
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Sign in to Nux Deck' });
    await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'a@example.com' } });
    await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'secret-pass' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByText('JBSWY3DPEHPK3PXP');
    expect(await violations(container)).toEqual([]);
  });
});
