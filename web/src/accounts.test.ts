// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { auth } from './lib/auth.svelte';
import { router } from './lib/router.svelte';
import {
  ADMIN,
  SESSION,
  anonymousRoutes,
  apiError,
  fakeServer,
  signedInRoutes,
} from './test-helpers';

beforeEach(() => {
  router.navigate('/');
  auth.pending = null;
  auth.recoveryCodes = null;
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function type(label: string, value: string): Promise<void> {
  await fireEvent.input(await screen.findByLabelText(label), { target: { value } });
}

describe('two-factor sign-in (ACC-2)', () => {
  const pending = {
    status: 200,
    body: { pending: { ticket: 't-1', expires_at: '2026-10-28T12:05:00Z', enrol_required: false } },
  };

  it('asks for the code after the password and signs in with it', async () => {
    const calls = fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': pending,
      'POST /api/v1/auth/totp/verify': { status: 200, body: SESSION },
      ...signedInRoutes,
      'GET /api/v1/me': { status: 401, body: {} },
    });
    render(App);
    await type('Email', 'ada@example.com');
    await type('Password', 'correct horse battery');
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('heading', { name: 'Two-factor authentication' })).toBeTruthy();
    const code = (await screen.findByLabelText('Code')) as HTMLInputElement;
    expect(code.autocomplete).toBe('one-time-code');
    await fireEvent.input(code, { target: { value: '123456' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Verify' }));

    await waitFor(() =>
      expect(calls.some((c) => c.path === '/api/v1/auth/totp/verify')).toBe(true),
    );
    const verify = calls.find((c) => c.path === '/api/v1/auth/totp/verify');
    expect(verify?.body).toEqual({ ticket: 't-1', code: '123456' });
  });

  it('shows a wrong code as an error with its code and stays on the step', async () => {
    fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': pending,
      'POST /api/v1/auth/totp/verify': apiError(
        401,
        'AUTH-TOTP-001',
        'Verification code not accepted',
        'Enter the current 6-digit code.',
      ),
    });
    render(App);
    await type('Email', 'ada@example.com');
    await type('Password', 'correct horse battery');
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await type('Code', '000000');
    await fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));

    expect(await screen.findByText('Error code: AUTH-TOTP-001')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Two-factor authentication' })).toBeTruthy();
  });

  it('shows the setup key when the server requires two-factor, then the recovery codes once', async () => {
    fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': {
        status: 200,
        body: { pending: { ticket: 't-2', expires_at: 'x', enrol_required: true } },
      },
      'POST /api/v1/auth/totp/enrol': {
        status: 200,
        body: {
          secret: 'JBSWY3DPEHPK3PXP',
          otpauth_uri: 'otpauth://totp/Nux:a?secret=JBSWY3DPEHPK3PXP',
        },
      },
      'POST /api/v1/auth/totp/verify': {
        status: 200,
        body: { ...SESSION, recovery_codes: ['AAAAA-BBBBB', 'CCCCC-DDDDD'] },
      },
    });
    render(App);
    await type('Email', 'ada@example.com');
    await type('Password', 'correct horse battery');
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    expect((await screen.findByLabelText('Setup key')).textContent).toBe('JBSWY3DPEHPK3PXP');
    await type('Code', '123456');
    await fireEvent.click(screen.getByRole('button', { name: 'Verify' }));

    expect(await screen.findByText('AAAAA-BBBBB')).toBeTruthy();
    const next = screen.getByRole('button', { name: 'Continue' }) as HTMLButtonElement;
    expect(next.disabled).toBe(true);
    await fireEvent.click(screen.getByLabelText('I have saved these codes'));
    expect(next.disabled).toBe(false);
  });
});

describe('users screen (ACC-1)', () => {
  const users = [
    {
      id: 'u1',
      email: 'ada@example.com',
      name: 'Ada Admin',
      role: 'admin',
      disabled: false,
      totp_enabled: true,
      created_at: '2026-10-01T00:00:00Z',
    },
    {
      id: 'u2',
      email: 'olivia@example.com',
      name: 'Olivia',
      role: 'operator',
      disabled: false,
      totp_enabled: false,
      created_at: '2026-10-02T00:00:00Z',
    },
  ];

  it('lists accounts, shows the last-admin error and toggles the 2FA requirement', async () => {
    const calls = fakeServer({
      ...signedInRoutes,
      'GET /api/v1/users': { status: 200, body: { users } },
      'GET /api/v1/settings/security': { status: 200, body: { require_2fa: false } },
      'PATCH /api/v1/users/u1': apiError(
        409,
        'AUTH-USER-002',
        'Last administrator',
        'Make another user an administrator first.',
      ),
      'PUT /api/v1/settings/security': { status: 200, body: { require_2fa: true } },
    });
    router.navigate('/settings/users');
    render(App);

    expect(await screen.findByRole('heading', { level: 1, name: 'Users' })).toBeTruthy();
    expect(await screen.findByText('olivia@example.com')).toBeTruthy();

    const disable = (await screen.findAllByRole('button', { name: 'Disable' })).at(0);
    await fireEvent.click(disable as HTMLElement);
    expect(await screen.findByText('Error code: AUTH-USER-002')).toBeTruthy();

    await fireEvent.click(screen.getByLabelText('Require two-factor authentication for everyone'));
    await waitFor(() =>
      expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({ require_2fa: true }),
    );
  });
});

describe('account screen (ACC-6, CLI-3)', () => {
  it('shows a new API token once and lists sessions with the current one marked', async () => {
    const tokens: unknown[] = [];
    fakeServer({
      ...signedInRoutes,
      'GET /api/v1/me/security': {
        status: 200,
        body: { totp_enabled: false, recovery_codes_left: 0, require_2fa: false },
      },
      'GET /api/v1/me/sessions': {
        status: 200,
        body: {
          sessions: [
            {
              id: 's1',
              created_at: '2026-10-28T10:00:00Z',
              last_seen_at: '2026-10-28T10:00:00Z',
              expires_at: '2026-11-04T10:00:00Z',
              ip: '203.0.113.5',
              user_agent: 'Firefox',
              current: true,
            },
          ],
        },
      },
      'GET /api/v1/me/tokens': () => ({ status: 200, body: { tokens } }),
      'POST /api/v1/me/tokens': () => {
        tokens.push({
          id: 't1',
          name: 'ci',
          bindings: [{ role: 'viewer', scope: {} }],
          created_at: 'x',
          expires_at: '2026-11-27T00:00:00Z',
          last_used_at: null,
        });
        return { status: 201, body: { token: 'nuxt_SECRETVALUE', details: tokens[0] } };
      },
    });
    router.navigate('/account');
    render(App);

    expect(await screen.findByText('(this session)')).toBeTruthy();
    expect(ADMIN.roles).toContain('admin');
    await type('Name', 'ci');
    await fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('nuxt_SECRETVALUE')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'I have copied it' }));
    expect(screen.queryByText('nuxt_SECRETVALUE')).toBeNull();
    expect(await screen.findByText('ci')).toBeTruthy();
  });
});
