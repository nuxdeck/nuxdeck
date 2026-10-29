// SPDX-License-Identifier: AGPL-3.0-only

/** The wizard steps after the administrator account (step 1 runs before sign-in, in routes/Setup.svelte). */
export type WizardStepId = 'address' | 'telemetry' | 'host' | 'done';

export const WIZARD_STEPS: readonly { id: WizardStepId; title: string }[] = [
  { id: 'address', title: 'Server address' },
  { id: 'telemetry', title: 'Telemetry' },
  { id: 'host', title: 'Add your first host' },
  { id: 'done', title: 'Done' },
];

export const SETUP_PATH = '/setup';

/** Where a returning administrator continues: past the address once it is saved. */
export function resumeStep(publicUrl: string): WizardStepId {
  return publicUrl === '' ? 'address' : 'telemetry';
}

/**
 * Mirrors the server's public URL rules (settingsapi.go normalizePublicURL) so the form can say why
 * an address is refused before it is sent. The server stays the authority and checks again.
 */
export function publicUrlProblem(raw: string): string | null {
  const value = raw.trim();
  if (value === '') {
    return 'Enter the address people open in the browser, such as https://nux.example.com:8443.';
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'Enter a full address that starts with https:// or http://.';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return 'Use an http or https address.';
  }
  if (url.hostname === '') {
    return 'Enter a host name or an IP address.';
  }
  if (url.username !== '' || url.password !== '') {
    return 'Remove the user name and password. Credentials never belong in the URL.';
  }
  if ((url.pathname !== '/' && url.pathname !== '') || url.search !== '' || url.hash !== '') {
    return 'Use the bare address with no path, query or fragment.';
  }
  return null;
}

/** The address as the server stores it: scheme and host, with an optional port. */
export function normalizedPublicUrl(raw: string): string {
  const url = new URL(raw.trim());
  return `${url.protocol}//${url.host}`;
}

/** What the next-steps checklist counts. A null count means this user cannot see that data. */
export interface ChecklistFacts {
  hosts: number;
  checks: number | null;
  channels: number | null;
  users: number | null;
  statusPages: number | null;
}

export interface ChecklistItem {
  id: 'host' | 'check' | 'channel' | 'user' | 'status-page';
  label: string;
  done: boolean;
  href: string;
}

/** The checklist items this user can see, each done when real data says so (docs/06-ux.md). */
export function checklistItems(facts: ChecklistFacts): ChecklistItem[] {
  const items: ChecklistItem[] = [
    { id: 'host', label: 'Add a host', done: facts.hosts > 0, href: '/inventory/add' },
    {
      id: 'check',
      label: 'Add an uptime check',
      done: (facts.checks ?? 0) > 0,
      href: '/checks/new',
    },
    {
      id: 'channel',
      label: 'Connect a notification channel',
      done: (facts.channels ?? 0) > 0,
      href: '/alerts/channels',
    },
    // One account is the administrator who is reading this; a second one means a teammate was invited.
    {
      id: 'user',
      label: 'Invite a teammate',
      done: (facts.users ?? 0) > 1,
      href: '/settings/users',
    },
    {
      id: 'status-page',
      label: 'Set up a status page',
      done: (facts.statusPages ?? 0) > 0,
      href: '/status-pages',
    },
  ];
  return items.filter((item) => factFor(facts, item.id) !== null);
}

function factFor(facts: ChecklistFacts, id: ChecklistItem['id']): number | null {
  switch (id) {
    case 'host':
      return facts.hosts;
    case 'check':
      return facts.checks;
    case 'channel':
      return facts.channels;
    case 'user':
      return facts.users;
    case 'status-page':
      return facts.statusPages;
  }
}

export function checklistOpen(items: readonly ChecklistItem[]): boolean {
  return items.some((item) => !item.done);
}

const DISMISSED_PREFIX = 'nux.checklist.dismissed.';

/** Storage can be blocked or missing (private windows, cleared site data); the checklist then just stays visible. */
function browserStorage(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}

export function isChecklistDismissed(
  userId: string,
  storage: Storage | null = browserStorage(),
): boolean {
  try {
    return storage?.getItem(DISMISSED_PREFIX + userId) === '1';
  } catch {
    return false;
  }
}

export function dismissChecklist(userId: string, storage: Storage | null = browserStorage()): void {
  try {
    storage?.setItem(DISMISSED_PREFIX + userId, '1');
  } catch {
    /* the dismissal lasts for this page view only */
  }
}
