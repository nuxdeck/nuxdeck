// SPDX-License-Identifier: AGPL-3.0-only

import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { auth } from '../lib/auth.svelte';

const list = vi.fn();
const create = vi.fn();
const remove = vi.fn();
vi.mock('../lib/api/client', async (orig) => ({
  ...(await orig<typeof import('../lib/api/client')>()),
  api: {
    roleBindings: () => list(),
    createRoleBinding: (b: unknown) => create(b),
    deleteRoleBinding: (id: string) => remove(id),
  },
}));

import RoleBindings, { describeScope, parseScope } from './RoleBindings.svelte';

describe('RoleBindings', () => {
  beforeEach(() => {
    list.mockReset().mockResolvedValue([
      {
        id: '01B1',
        subject_type: 'oidc_group',
        subject: 'sre',
        role: 'viewer',
        scope: { environments: ['staging'] },
      },
    ]);
    create.mockReset().mockResolvedValue({});
    remove.mockReset().mockResolvedValue(undefined);
    auth.user = { id: '1', email: 'a@b.c', name: 'A', roles: ['admin'] };
  });

  it('ACC-5 parses and describes scopes', () => {
    expect(parseScope('staging, qa', 'team:web, tier:1\n\nowner')).toEqual({
      environments: ['staging', 'qa'],
      tag_sets: [['team:web', 'tier:1'], ['owner']],
    });
    expect(parseScope('', '  ')).toEqual({});
    expect(describeScope({})).toBe('Everything');
    expect(describeScope({ environments: ['staging'], tag_sets: [['a:b', 'c']] })).toBe(
      'env: staging; tags: a:b + c',
    );
  });

  it('ACC-5 lists bindings with their scope and adds one', async () => {
    render(RoleBindings);
    expect(await screen.findByText('env: staging')).toBeTruthy();

    await fireEvent.input(screen.getByLabelText(/Group name/), { target: { value: 'ops' } });
    await fireEvent.input(screen.getByLabelText(/Environments/), { target: { value: 'staging' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add role binding' }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        subject_type: 'oidc_group',
        subject: 'ops',
        role: 'viewer',
        scope: { environments: ['staging'] },
      }),
    );
  });

  it('removes a binding and requires a subject to add', async () => {
    render(RoleBindings);
    await fireEvent.click(await screen.findByRole('button', { name: /Remove/ }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith('01B1'));

    await fireEvent.click(screen.getByRole('button', { name: 'Add role binding' }));
    expect(await screen.findByText('Enter a user ID or group name.')).toBeTruthy();
    expect(create).not.toHaveBeenCalled();
  });

  it('shows nothing to non-admins', () => {
    auth.user = { id: '2', email: 'v@b.c', name: 'V', roles: ['viewer'] };
    render(RoleBindings);
    expect(screen.getByText('Only administrators can manage roles.')).toBeTruthy();
    expect(list).not.toHaveBeenCalled();
  });
});
