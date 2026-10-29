// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import {
  checklistItems,
  checklistOpen,
  dismissChecklist,
  isChecklistDismissed,
  normalizedPublicUrl,
  publicUrlProblem,
  resumeStep,
} from './onboarding';

const none = { hosts: 0, checks: 0, channels: 0, users: 1, statusPages: 0 };

describe('INS-3 public URL rules', () => {
  it.each(['https://nux.example.com', 'https://nux.example.com:8443/', 'http://10.0.0.5:8443'])(
    'accepts %s',
    (value) => {
      expect(publicUrlProblem(value)).toBeNull();
    },
  );

  it.each([
    ['', 'Enter the address'],
    ['nux.example.com', 'full address'],
    ['ftp://nux.example.com', 'http or https'],
    ['https://admin:secret@nux.example.com', 'Credentials'],
    ['https://nux.example.com/path', 'bare address'],
    ['https://nux.example.com?x=1', 'bare address'],
    ['https://nux.example.com#top', 'bare address'],
    ['https://', 'full address'],
  ])('refuses %j with a reason', (value, reason) => {
    expect(publicUrlProblem(value)).toContain(reason);
  });

  it('stores scheme and host only', () => {
    expect(normalizedPublicUrl(' https://nux.example.com:8443/ ')).toBe(
      'https://nux.example.com:8443',
    );
  });
});

describe('INS-3 resumable steps', () => {
  it('starts at the address when none is saved, otherwise at telemetry', () => {
    expect(resumeStep('')).toBe('address');
    expect(resumeStep('https://nux.example.com')).toBe('telemetry');
  });
});

describe('INS-4 checklist derivation', () => {
  it('reports every item open for a new install', () => {
    const items = checklistItems({ hosts: 0, checks: 0, channels: 0, users: 1, statusPages: 0 });
    expect(items.map((i) => i.id)).toEqual(['host', 'check', 'channel', 'user', 'status-page']);
    expect(items.every((i) => !i.done)).toBe(true);
    expect(checklistOpen(items)).toBe(true);
  });

  it('marks items done from real counts', () => {
    const items = checklistItems({ hosts: 2, checks: 1, channels: 0, users: 3, statusPages: 1 });
    expect(Object.fromEntries(items.map((i) => [i.id, i.done]))).toEqual({
      host: true,
      check: true,
      channel: false,
      user: true,
      'status-page': true,
    });
    expect(checklistOpen(items)).toBe(true);
  });

  it('closes when everything is done', () => {
    const items = checklistItems({ hosts: 1, checks: 1, channels: 1, users: 2, statusPages: 1 });
    expect(checklistOpen(items)).toBe(false);
  });

  it('omits items the user cannot see (null counts) instead of marking them open', () => {
    const items = checklistItems({ ...none, users: null, channels: null });
    expect(items.map((i) => i.id)).toEqual(['host', 'check', 'status-page']);
  });

  it('links each item to the screen that does it', () => {
    const hrefs = checklistItems(none).map((i) => i.href);
    expect(hrefs).toEqual([
      '/inventory/add',
      '/checks/new',
      '/alerts/channels',
      '/settings/users',
      '/status-pages',
    ]);
  });
});

describe('INS-4 checklist dismissal', () => {
  function memory(): Storage {
    const data = new Map<string, string>();
    return {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
    } as unknown as Storage;
  }

  it('remembers the dismissal per user', () => {
    const storage = memory();
    expect(isChecklistDismissed('u1', storage)).toBe(false);
    dismissChecklist('u1', storage);
    expect(isChecklistDismissed('u1', storage)).toBe(true);
    expect(isChecklistDismissed('u2', storage)).toBe(false);
  });

  it('treats blocked storage as not dismissed and never throws', () => {
    const blocked = {
      getItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
    } as unknown as Storage;
    expect(isChecklistDismissed('u1', blocked)).toBe(false);
    expect(() => dismissChecklist('u1', blocked)).not.toThrow();
    expect(isChecklistDismissed('u1', null)).toBe(false);
  });
});
