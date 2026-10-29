// SPDX-License-Identifier: AGPL-3.0-only

import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { auth } from '../lib/auth.svelte';
import { inventory } from '../lib/inventory.svelte';

const settings = vi.fn();
const setSetupCompleted = vi.fn();
const telemetryPreview = vi.fn();
const setPublicUrl = vi.fn();
vi.mock('../lib/api/client', async (orig) => ({
  ...(await orig<typeof import('../lib/api/client')>()),
  api: {
    settings: () => settings(),
    setSetupCompleted: (v: boolean) => setSetupCompleted(v),
    telemetryPreview: () => telemetryPreview(),
    setPublicUrl: (v: string) => setPublicUrl(v),
    setTelemetryEnabled: vi.fn().mockResolvedValue({}),
  },
}));

import SetupWizard from './SetupWizard.svelte';

const base = { 'telemetry.enabled': false, 'telemetry.locked': false };

describe('INS-3 setup wizard', () => {
  beforeEach(() => {
    settings.mockReset();
    setSetupCompleted.mockReset().mockResolvedValue({ ...base, 'setup.completed': true });
    setPublicUrl.mockReset().mockResolvedValue({});
    telemetryPreview.mockReset().mockResolvedValue({});
    inventory.loaded = true;
    inventory.hosts = [];
    auth.user = { id: 'u1', email: 'a@b.c', name: 'A', roles: ['admin'] };
  });

  it('is closed to people who are not administrators', () => {
    auth.user = { id: 'u2', email: 'v@b.c', name: 'V', roles: ['viewer'] };
    render(SetupWizard);
    expect(screen.getByRole('heading', { name: 'Administrators only' })).toBeTruthy();
    expect(settings).not.toHaveBeenCalled();
  });

  it('starts at the server address when none is saved', async () => {
    settings.mockResolvedValue({ ...base, 'server.public_url': '', 'setup.completed': false });
    render(SetupWizard);
    expect(await screen.findByRole('heading', { name: 'Server address' })).toBeTruthy();
    expect(screen.getByText(/Step 2 of 5/)).toBeTruthy();
  });

  it('resumes at telemetry once the address is saved', async () => {
    settings.mockResolvedValue({
      ...base,
      'server.public_url': 'https://nux.example.com',
      'setup.completed': false,
    });
    render(SetupWizard);
    expect(await screen.findByRole('heading', { name: 'Telemetry' })).toBeTruthy();
  });

  it('moves focus to the new step heading on each change', async () => {
    settings.mockResolvedValue({ ...base, 'server.public_url': '', 'setup.completed': false });
    render(SetupWizard);
    const heading = await screen.findByRole('heading', { name: 'Server address' });
    await waitFor(() => expect(document.activeElement).toBe(heading));
  });

  it('finishes from the host step by recording setup.completed', async () => {
    settings.mockResolvedValue({
      ...base,
      'server.public_url': 'https://nux.example.com',
      'setup.completed': false,
    });
    render(SetupWizard);
    await screen.findByRole('heading', { name: 'Telemetry' });
    await fireEvent.click(screen.getByRole('button', { name: 'Skip for now' }));
    await screen.findByRole('heading', { name: 'Add your first host' });
    await fireEvent.click(screen.getByRole('button', { name: 'Finish setup' }));
    expect(await screen.findByRole('heading', { name: 'Setup is complete' })).toBeTruthy();
    expect(setSetupCompleted).toHaveBeenCalledWith(true);
  });

  it('shows a finished setup as done', async () => {
    settings.mockResolvedValue({
      ...base,
      'server.public_url': 'https://n.example',
      'setup.completed': true,
    });
    render(SetupWizard);
    expect(await screen.findByRole('heading', { name: 'Setup is complete' })).toBeTruthy();
  });
});
