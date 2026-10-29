// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { router } from './lib/router.svelte';
import { apiError, fakeServer, signedInRoutes } from './test-helpers';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  router.navigate('/');
});

const PREVIEW = { schema_version: 1, install_id: '00000000-0000-4000-8000-000000000000' };

describe('TEL-1 telemetry panel', () => {
  it('shows the toggle off and the exact payload, and enabling is sent to the API', async () => {
    let enabled = false;
    const calls = fakeServer({
      ...signedInRoutes,
      'GET /api/v1/settings': () => ({
        status: 200,
        body: { 'telemetry.enabled': enabled, 'telemetry.locked': false },
      }),
      'GET /api/v1/telemetry/preview': { status: 200, body: PREVIEW },
      'PUT /api/v1/settings': (c) => {
        enabled = (c.body as { value: boolean }).value;
        return { status: 200, body: { 'telemetry.enabled': enabled, 'telemetry.locked': false } };
      },
    });
    router.navigate('/settings');
    const { container } = render(App);
    const box = await screen.findByRole('checkbox', { name: /daily diagnostic report/i });
    expect((box as HTMLInputElement).checked).toBe(false);
    await waitFor(() =>
      expect(container.querySelector('pre code')?.textContent).toBe(
        JSON.stringify(PREVIEW, null, 2),
      ),
    );
    await fireEvent.click(box);
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({
      key: 'telemetry.enabled',
      value: true,
    });
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it('reverts the toggle and shows the code when the change fails', async () => {
    fakeServer({
      ...signedInRoutes,
      'GET /api/v1/settings': {
        status: 200,
        body: { 'telemetry.enabled': false, 'telemetry.locked': false },
      },
      'GET /api/v1/telemetry/preview': { status: 200, body: PREVIEW },
      'PUT /api/v1/settings': apiError(500, 'API-INT-001', 'Internal error', 'Try again.'),
    });
    router.navigate('/settings');
    render(App);
    const box = await screen.findByRole('checkbox', { name: /daily diagnostic report/i });
    await fireEvent.click(box);
    await screen.findByText(/API-INT-001/);
    expect((box as HTMLInputElement).checked).toBe(false);
  });
});
