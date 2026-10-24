// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { router, sections } from './lib/router.svelte';
import { appearance } from './lib/theme.svelte';
import { fakeServer, signedInRoutes } from './test-helpers';

function resetUi(): void {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  router.navigate('/');
  while (appearance.theme !== 'system') appearance.cycleTheme();
  if (appearance.density === 'compact') appearance.toggleDensity();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.density;
  window.localStorage.clear();
}

async function renderShell(): Promise<void> {
  fakeServer(signedInRoutes);
  render(App);
  await screen.findByRole('navigation', { name: 'Main' });
}

beforeEach(resetUi);
afterEach(resetUi);

describe('app shell', () => {
  it('lists the seven sections in order', async () => {
    await renderShell();
    const nav = screen.getByRole('navigation', { name: 'Main' });
    const names = Array.from(nav.querySelectorAll('a')).map((a) => a.textContent?.trim());
    expect(names).toEqual(sections.map((s) => s.title));
    expect(names).toHaveLength(7);
  });

  it('marks the current page and shows its heading', async () => {
    await renderShell();
    expect(screen.getByRole('link', { name: 'Overview' }).getAttribute('aria-current')).toBe(
      'page',
    );
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Overview');
  });

  it('navigates without a reload, updates the title and moves focus to the heading', async () => {
    await renderShell();
    await fireEvent.click(screen.getByRole('link', { name: 'Inventory' }));

    const heading = await screen.findByRole('heading', { level: 1, name: 'Inventory' });
    expect(window.location.pathname).toBe('/inventory');
    expect(document.title).toBe('Inventory · Nux Deck');
    expect(screen.getByRole('link', { name: 'Inventory' }).getAttribute('aria-current')).toBe(
      'page',
    );
    expect(screen.getByRole('link', { name: 'Overview' }).hasAttribute('aria-current')).toBe(false);
    await new Promise((r) => setTimeout(r, 0));
    expect(document.activeElement).toBe(heading);
  });

  it('shows a not-found page for unknown paths', async () => {
    router.navigate('/nope');
    await renderShell();
    expect(await screen.findByRole('heading', { level: 1, name: 'Page not found' })).toBeTruthy();
    expect(document.title).toBe('Page not found · Nux Deck');
  });

  it('offers a skip link to the main content', async () => {
    await renderShell();
    const skip = screen.getByRole('link', { name: 'Skip to main content' });
    expect(skip.getAttribute('href')).toBe('#main');
    expect(document.getElementById('main')).toBeTruthy();
  });

  it('collapses the sidebar, keeps names accessible and remembers the choice', async () => {
    await renderShell();
    const toggle = screen.getByRole('button', { name: 'Toggle sidebar' });
    const before = toggle.getAttribute('aria-expanded');
    await fireEvent.click(toggle);

    expect(toggle.getAttribute('aria-expanded')).not.toBe(before);
    const stored = window.localStorage.getItem('nux.sidebar');
    expect(stored === 'collapsed' || stored === 'expanded').toBe(true);
    expect(screen.getByRole('link', { name: 'Overview' })).toBeTruthy();
  });
});

describe('appearance', () => {
  it('cycles system, light, dark and persists the choice', async () => {
    await renderShell();
    const button = () => screen.getByRole('button', { name: /^Theme:/ });
    expect(button().getAttribute('aria-label')).toContain('system');

    await fireEvent.click(button());
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(window.localStorage.getItem('nux.theme')).toBe('light');

    await fireEvent.click(button());
    expect(document.documentElement.dataset.theme).toBe('dark');

    await fireEvent.click(button());
    expect(document.documentElement.dataset.theme).toBeUndefined();
    expect(button().getAttribute('aria-label')).toContain('system');
  });

  it('switches row density', async () => {
    await renderShell();
    await fireEvent.click(screen.getByRole('button', { name: /^Row density:/ }));
    expect(document.documentElement.dataset.density).toBe('compact');
    expect(window.localStorage.getItem('nux.density')).toBe('compact');
  });
});
