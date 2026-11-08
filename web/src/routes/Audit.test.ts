// SPDX-License-Identifier: AGPL-3.0-only

import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { auditExportUrl, type AuditEntry } from '../lib/api/client';
import { auth } from '../lib/auth.svelte';

const entry: AuditEntry = {
  id: 7,
  ts: '2026-10-28T12:00:00Z',
  actor_type: 'user',
  actor_id: '01ABC',
  action: 'check.create',
  target_type: 'check',
  target_id: '01CHK',
  ip: '203.0.113.9',
  result: 'success',
  details: { name: 'API', token: '[redacted]' },
  prev_hash: 'aa',
  hash: 'bb',
};

const search = vi.fn();
const verify = vi.fn();
vi.mock('../lib/api/client', async (orig) => ({
  ...(await orig<typeof import('../lib/api/client')>()),
  api: { auditSearch: (...a: unknown[]) => search(...a), auditVerify: () => verify() },
}));

import Audit from './Audit.svelte';

describe('Audit', () => {
  beforeEach(() => {
    search.mockReset().mockResolvedValue({ items: [entry], next_cursor: null });
    verify.mockReset().mockResolvedValue({ ok: true, entries: 1 });
    auth.user = { id: '1', email: 'a@b.c', name: 'A', roles: ['admin'] };
  });

  it('AUD-3 lists entries, shows the chain badge and opens the detail drawer', async () => {
    render(Audit);
    expect(await screen.findByText('check.create')).toBeTruthy();
    expect(await screen.findByText('Chain verified')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: /Details of entry 7/ }));
    expect(screen.getByRole('complementary', { name: /Entry/ }).textContent).toContain(
      '[redacted]',
    );
  });

  it('AUD-2 flags a broken chain', async () => {
    verify.mockResolvedValue({
      ok: false,
      entries: 3,
      broken_at: 2,
      reason: 'modified',
      code: 'AUD-CHAIN-001',
    });
    render(Audit);
    expect(await screen.findByText('Chain broken')).toBeTruthy();
  });

  it('AUD-3 sends the filters', async () => {
    render(Audit);
    await fireEvent.input(await screen.findByLabelText('Actor ID'), { target: { value: '01ABC' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() =>
      expect(search).toHaveBeenLastCalledWith(expect.objectContaining({ actor: '01ABC' })),
    );
  });

  it('does not query for non-admins', () => {
    auth.user = { id: '2', email: 'v@b.c', name: 'V', roles: ['viewer'] };
    render(Audit);
    expect(screen.getByText('Administrators only')).toBeTruthy();
    expect(search).not.toHaveBeenCalled();
  });

  it('builds the export URL without paging fields', () => {
    expect(auditExportUrl({ actor: 'u', limit: 50, cursor: '9', result: '' })).toBe(
      '/api/v1/audit/export?actor=u',
    );
  });
});
