// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, render, screen } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { router, sections } from './lib/router.svelte';
import { anonymousRoutes, emptyList, fakeServer, signedInRoutes, SESSION } from './test-helpers';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

// Colour contrast is not computed by jsdom; contrast.test.ts covers it from the tokens.
async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, {
    rules: { 'color-contrast': { enabled: false } },
  });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
  );
}

/**
 * Screens that have no fixture of their own get an empty list for reads and an empty
 * object for writes, so every route renders its default state.
 */
const fallbackRoutes = {
  ...signedInRoutes,
  'GET /api/v1/me': { status: 200, body: SESSION },
  'GET /api/v1/users': emptyList,
  'GET /api/v1/rolebindings': emptyList,
  'GET /api/v1/me/tokens': emptyList,
  'GET /api/v1/me/sessions': emptyList,
  'GET /api/v1/audit': emptyList,
  'GET /api/v1/checks?limit=500': emptyList,
  'GET /api/v1/status-pages': emptyList,
  'GET /api/v1/alerts?state=active&limit=200': emptyList,
  'GET /api/v1/rules?limit=500': emptyList,
  'GET /api/v1/channels?limit=500': emptyList,
  'GET /api/v1/silences?limit=200&active=true': emptyList,
  'GET /api/v1/routes': { status: 200, body: { routes: [] } },
  'GET /api/v1/settings': { status: 200, body: {} },
  'GET /api/v1/settings/security': { status: 200, body: {} },
  'GET /api/v1/telemetry/preview': { status: 200, body: {} },
};

const signedInPaths = [
  ...sections.map((s) => s.path),
  '/account',
  '/settings/users',
  '/alerts/rules',
  '/alerts/silences',
  '/alerts/channels',
  '/alerts/routes',
  '/inventory/add',
  '/checks/new',
  '/not-a-page',
];

describe('accessibility of every signed-in route (axe, WCAG 2.2 AA tags)', () => {
  it.each(signedInPaths)('has no violations on %s', async (path) => {
    router.navigate(path);
    fakeServer(fallbackRoutes);
    const { container } = render(App);
    await screen.findByRole('navigation', { name: 'Main' });
    expect(container.querySelector('h1'), 'page heading').not.toBeNull();
    expect(await violations(container)).toEqual([]);
  });
});

describe('accessibility of the anonymous screens', () => {
  it.each([false, true])(
    'has no violations on the sign-in screen (setup required: %s)',
    async (setup) => {
      fakeServer(anonymousRoutes(setup));
      const { container } = render(App);
      await screen.findByRole('heading', { level: 1 });
      expect(await violations(container)).toEqual([]);
    },
  );
});
