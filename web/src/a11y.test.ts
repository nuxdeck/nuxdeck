// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { router, sections } from './lib/router.svelte';
import { anonymousRoutes, apiError, fakeServer, signedInRoutes } from './test-helpers';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

// Colour contrast cannot be computed in jsdom; tokens.test.ts checks it from the tokens instead.
async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, {
    rules: { 'color-contrast': { enabled: false } },
  });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
  );
}

describe('accessibility (axe, WCAG 2.2 AA tags)', () => {
  it.each([...sections.map((s) => s.path), '/not-a-page'])(
    'has no violations on %s',
    async (path) => {
      router.navigate(path);
      fakeServer(signedInRoutes);
      const { container } = render(App);
      await screen.findByRole('navigation', { name: 'Main' });
      expect(await violations(container)).toEqual([]);
    },
  );
});

describe('accessibility of the sign-in and setup screens', () => {
  it('has no violations on the sign-in form, with and without an error', async () => {
    fakeServer({
      ...anonymousRoutes(false),
      'POST /api/v1/auth/login': apiError(
        401,
        'AUTH-DENY-001',
        'The email or password is incorrect.',
        'Check them and try again.',
      ),
    });
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Sign in to Nux Deck' });
    expect(await violations(container)).toEqual([]);

    await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'a@example.com' } });
    await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'x' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByRole('alert');
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on the setup wizard, with a field error', async () => {
    fakeServer({
      ...anonymousRoutes(true),
      'POST /api/v1/setup/admin': apiError(
        422,
        'AUTH-PWD-001',
        'Password not accepted.',
        'Too short.',
        'password',
      ),
    });
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Set up Nux Deck' });
    expect(await violations(container)).toEqual([]);

    for (const [label, value] of [
      ['Setup token', 't'],
      ['Your name', 'Ada'],
      ['Email', 'a@example.com'],
      ['Password', 'short'],
    ]) {
      await fireEvent.input(screen.getByLabelText(label as string), { target: { value } });
    }
    await fireEvent.click(screen.getByRole('button', { name: 'Create administrator' }));
    await screen.findByText(/Password not accepted/);
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on the unreachable screen', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('down');
      }),
    );
    const { container } = render(App);
    await screen.findByRole('heading', { name: 'Cannot reach the server' });
    expect(await violations(container)).toEqual([]);
  });
});
