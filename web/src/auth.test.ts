// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { router } from './lib/router.svelte';
import { ADMIN, SESSION, anonymousRoutes, apiError, fakeServer } from './test-helpers';

beforeEach(() => {
  router.navigate('/');
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function type(label: string, value: string): Promise<HTMLInputElement> {
  const input = (await screen.findByLabelText(label)) as HTMLInputElement;
  await fireEvent.input(input, { target: { value } });
  return input;
}

describe('sign in', () => {
  it('shows the sign-in form to an anonymous visitor', async () => {
    fakeServer(anonymousRoutes(false));
    render(App);

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Sign in to Nux Deck' }),
    ).toBeTruthy();
    expect(document.title).toBe('Sign in · Nux Deck');
    const email = screen.getByLabelText('Email') as HTMLInputElement;
    const password = screen.getByLabelText('Password') as HTMLInputElement;
    // Password managers and the WCAG 3.3.8 requirement depend on these hints.
    expect(email.autocomplete).toBe('username');
    expect(password.autocomplete).toBe('current-password');
    expect(password.type).toBe('password');
  });

  it('signs in and shows the app', async () => {
    const calls = fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': { status: 200, body: SESSION },
    });
    render(App);
    await type('Email', 'ada@example.com');
    await type('Password', 'correct horse battery');
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('navigation', { name: 'Main' })).toBeTruthy();
    expect(screen.getByText(ADMIN.name)).toBeTruthy();
    const login = calls.find((c) => c.path === '/api/v1/auth/login');
    expect(login?.body).toEqual({ email: 'ada@example.com', password: 'correct horse battery' });
    expect(login?.headers['X-CSRF-Token']).toBeUndefined(); // there is no session yet
  });

  it('explains a failed sign-in with the error code and keeps the email', async () => {
    fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': apiError(
        401,
        'AUTH-DENY-001',
        'The email or password is incorrect.',
        'Check the email and password and try again.',
      ),
    });
    render(App);
    await type('Email', 'ada@example.com');
    await type('Password', 'wrong password here');
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('The email or password is incorrect.');
    expect(alert.textContent).toContain('Check the email and password and try again.');
    expect(alert.textContent).toContain('AUTH-DENY-001');
    expect((screen.getByLabelText('Email') as HTMLInputElement).value).toBe('ada@example.com');
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
    expect(screen.queryByRole('navigation', { name: 'Main' })).toBeNull();
  });

  it('disables the form while the request is in flight', async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': async () => {
        await gate;
        return { status: 200, body: SESSION };
      },
    });
    render(App);
    await type('Email', 'ada@example.com');
    await type('Password', 'correct horse battery');
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    const busy = await screen.findByRole('button', { name: 'Signing in…' });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    release();
    await screen.findByRole('navigation', { name: 'Main' });
  });
});

describe('sign out', () => {
  it('sends the CSRF token, then returns to the sign-in form', async () => {
    const calls = fakeServer({
      'GET /api/v1/me': { status: 200, body: SESSION },
      'POST /api/v1/auth/logout': { status: 204 },
      'GET /api/v1/setup/status': { status: 200, body: { setup_required: false } },
    });
    render(App);
    await fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }));

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Sign in to Nux Deck' }),
    ).toBeTruthy();
    const logout = calls.find((c) => c.path === '/api/v1/auth/logout');
    expect(logout?.headers['X-CSRF-Token']).toBe(SESSION.csrf_token);
  });

  it('signs out locally even if the server call fails', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    fakeServer({
      'GET /api/v1/me': { status: 200, body: SESSION },
      'POST /api/v1/auth/logout': apiError(
        500,
        'API-INT-001',
        'Something went wrong on the server.',
        'Try again.',
      ),
    });
    render(App);
    await fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Sign in to Nux Deck' }),
    ).toBeTruthy();
    expect(warn).toHaveBeenCalledWith('sign-out request failed', 'API-INT-001');
    warn.mockRestore();
  });
});

describe('first-run setup', () => {
  async function fillSetup(
    overrides: Partial<Record<'Setup token' | 'Your name' | 'Email' | 'Password', string>> = {},
  ) {
    const v = {
      'Setup token': 'tok123',
      'Your name': 'Ada Admin',
      Email: 'ada@example.com',
      Password: 'correct horse battery',
      ...overrides,
    };
    for (const [label, value] of Object.entries(v)) await type(label, value);
  }

  it('shows the wizard and tells the operator where the token comes from', async () => {
    fakeServer(anonymousRoutes(true));
    render(App);

    expect(await screen.findByRole('heading', { level: 1, name: 'Set up Nux Deck' })).toBeTruthy();
    expect(screen.getByText(/Step 1 of 5/)).toBeTruthy();
    expect(screen.getByText(/nuxd setup-token/)).toBeTruthy();
    expect((screen.getByLabelText('Password') as HTMLInputElement).autocomplete).toBe(
      'new-password',
    );
  });

  it('gives live password feedback', async () => {
    fakeServer(anonymousRoutes(true));
    render(App);
    await type('Password', 'short');
    expect(screen.getByText('7 more characters needed.')).toBeTruthy();
    await type('Password', 'correct horse battery');
    expect(screen.getByText(/Long enough/)).toBeTruthy();
  });

  it('creates the administrator and signs in', async () => {
    const calls = fakeServer({
      ...anonymousRoutes(true),
      'POST /api/v1/setup/admin': { status: 201, body: SESSION },
    });
    render(App);
    await fillSetup();
    await fireEvent.click(screen.getByRole('button', { name: 'Create administrator' }));

    expect(await screen.findByRole('navigation', { name: 'Main' })).toBeTruthy();
    expect(calls.find((c) => c.path === '/api/v1/setup/admin')?.body).toEqual({
      token: 'tok123',
      name: 'Ada Admin',
      email: 'ada@example.com',
      password: 'correct horse battery',
    });
  });

  it('ties a server-side field error to its input', async () => {
    fakeServer({
      ...anonymousRoutes(true),
      'POST /api/v1/setup/admin': apiError(
        422,
        'AUTH-PWD-001',
        'The password does not meet the password policy.',
        'this password appears in lists of breached passwords; choose another',
        'password',
      ),
    });
    render(App);
    await fillSetup({ Password: '123qweasdzxc' });
    await fireEvent.click(screen.getByRole('button', { name: 'Create administrator' }));

    await waitFor(() =>
      expect(screen.getByLabelText('Password').getAttribute('aria-invalid')).toBe('true'),
    );
    const input = screen.getByLabelText('Password');
    const message = document.getElementById(
      input.getAttribute('aria-describedby')!.split(' ').pop()!,
    );
    expect(message?.textContent).toContain('breached');
    expect(screen.getByLabelText('Email').getAttribute('aria-invalid')).toBeNull();
  });

  it('reports a wrong setup token in the alert', async () => {
    fakeServer({
      ...anonymousRoutes(true),
      'POST /api/v1/setup/admin': apiError(
        403,
        'AUTH-SETUP-001',
        'The setup token is missing or wrong.',
        'Run nuxd setup-token on the server and paste its output.',
      ),
    });
    render(App);
    await fillSetup({ 'Setup token': 'nope' });
    await fireEvent.click(screen.getByRole('button', { name: 'Create administrator' }));

    expect((await screen.findByRole('alert')).textContent).toContain('AUTH-SETUP-001');
  });
});

describe('server problems', () => {
  it('offers a retry when the server cannot be reached', async () => {
    let up = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        if (!up) throw new TypeError('network down');
        if (String(input).endsWith('/me'))
          return new Response(JSON.stringify(SESSION), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        throw new Error('unexpected');
      }),
    );
    render(App);

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Cannot reach the server' }),
    ).toBeTruthy();
    expect((await screen.findByRole('alert')).textContent).toContain('NETWORK');
    expect(document.title).toBe('Cannot reach the server · Nux Deck');

    up = true;
    await fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('navigation', { name: 'Main' })).toBeTruthy();
  });

  it('treats an unexpected server error as unreachable, not as signed out', async () => {
    fakeServer({
      'GET /api/v1/me': apiError(
        500,
        'API-INT-001',
        'Something went wrong on the server.',
        'Try again.',
      ),
    });
    render(App);
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Cannot reach the server' }),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Password')).toBeNull();
  });
});
