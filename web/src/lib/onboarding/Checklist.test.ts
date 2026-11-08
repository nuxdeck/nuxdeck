// SPDX-License-Identifier: AGPL-3.0-only

import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { auth } from '../auth.svelte';
import { inventory } from '../inventory.svelte';

const checks = vi.fn();
const channels = vi.fn();
const users = vi.fn();
const statusPages = vi.fn();
vi.mock('../api/client', async (orig) => ({
  ...(await orig<typeof import('../api/client')>()),
  api: {
    checks: () => checks(),
    channels: () => channels(),
    users: () => users(),
    statusPages: () => statusPages(),
  },
}));

import Checklist from './Checklist.svelte';

const admin = { id: 'u1', email: 'a@b.c', name: 'A', roles: ['admin'] };

describe('INS-4 next-steps checklist', () => {
  beforeEach(() => {
    window.localStorage.clear();
    auth.user = admin;
    inventory.loaded = true;
    inventory.hosts = [];
    checks.mockReset().mockResolvedValue([]);
    channels.mockReset().mockResolvedValue([]);
    users.mockReset().mockResolvedValue([{ id: 'u1' }]);
    statusPages.mockReset().mockResolvedValue([]);
  });

  it('lists the open steps with text as well as a state label', async () => {
    render(Checklist);
    expect(await screen.findByRole('heading', { name: /Next steps/ }));
    expect(screen.getByRole('link', { name: 'Add an uptime check' }).getAttribute('href')).toBe(
      '/checks/new',
    );
    expect(screen.getAllByText('To do')).toHaveLength(5);
  });

  it('marks items done from real data and hides when everything is done', async () => {
    inventory.hosts = [{ id: 'h1' }] as never;
    checks.mockResolvedValue([{ id: 'c1' }]);
    channels.mockResolvedValue([{ id: 'ch1' }]);
    users.mockResolvedValue([{ id: 'u1' }, { id: 'u2' }]);
    statusPages.mockResolvedValue([{ id: 'p1' }]);
    const { container } = render(Checklist);
    await waitFor(() => expect(container.querySelector('section')).toBeNull());
  });

  it('leaves out items the user cannot read', async () => {
    auth.user = { ...admin, roles: ['viewer'] };
    users.mockReset();
    render(Checklist);
    await screen.findByRole('heading', { name: /Next steps/ });
    expect(screen.queryByText('Invite a teammate')).toBeNull();
    expect(users).not.toHaveBeenCalled();
  });

  it('stays dismissed for the same user after a reload', async () => {
    const first = render(Checklist);
    await fireEvent.click(await screen.findByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByRole('heading', { name: /Next steps/ })).toBeNull();
    first.unmount();

    render(Checklist);
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole('heading', { name: /Next steps/ })).toBeNull();
  });

  it('shows again to a different user', async () => {
    window.localStorage.setItem('nux.checklist.dismissed.u1', '1');
    auth.user = { ...admin, id: 'u2' };
    render(Checklist);
    expect(await screen.findByRole('heading', { name: /Next steps/ }));
  });
});
