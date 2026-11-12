// SPDX-License-Identifier: AGPL-3.0-only

import { vi } from 'vitest';

export interface Call {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

export interface Reply {
  status: number;
  body?: unknown;
  /** Extra response headers, such as ETag or Retry-After. */
  headers?: Record<string, string>;
}

export type Handler = (call: Call) => Reply | Promise<Reply>;

export const ADMIN = { id: 'u1', email: 'ada@example.com', name: 'Ada Admin', roles: ['admin'] };
export const SESSION = { user: ADMIN, csrf_token: 'csrf-token-1' };

export function apiError(
  status: number,
  code: string,
  message: string,
  hint: string,
  field?: string,
): Reply {
  return { status, body: { error: { code, message, hint, ...(field ? { field } : {}) } } };
}

/** Replaces fetch with a fake nuxd. Routes are keyed "METHOD /path"; anything else fails the test. */
export function fakeServer(routes: Record<string, Handler | Reply>) {
  const calls: Call[] = [];
  fakeEvents();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      const path = String(input);
      const call: Call = {
        method,
        path,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
        headers: { ...(init?.headers as Record<string, string> | undefined) },
      };
      calls.push(call);
      const route = routes[`${method} ${path}`];
      if (!route) throw new Error(`unexpected request: ${method} ${path}`);
      const reply = typeof route === 'function' ? await route(call) : route;
      if (reply.status === 204) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'Content-Type': 'application/json', ...reply.headers },
      });
    }),
  );
  return calls;
}

/** A stand-in for the browser's EventSource that tests drive by hand. */
export class FakeEventSource {
  static instances: FakeEventSource[] = [];
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  readyState = 0;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  private listeners = new Map<string, ((e: MessageEvent<string>) => void)[]>();

  constructor(readonly url: string) {
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, fn: (e: MessageEvent<string>) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }

  close(): void {
    this.readyState = FakeEventSource.CLOSED;
  }

  // --- test controls ---
  open(): void {
    this.readyState = FakeEventSource.OPEN;
    this.onopen?.();
  }

  emit(type: string, payload: unknown): void {
    const data =
      typeof payload === 'string' ? payload : JSON.stringify({ type, ...(payload as object) });
    for (const fn of this.listeners.get(type) ?? []) fn(new MessageEvent(type, { data }));
  }

  fail(fatal = false): void {
    this.readyState = fatal ? FakeEventSource.CLOSED : FakeEventSource.CONNECTING;
    this.onerror?.();
  }

  static get current(): FakeEventSource {
    const last = FakeEventSource.instances.at(-1);
    if (!last) throw new Error('no EventSource was opened');
    return last;
  }
}

export function fakeEvents(): void {
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
}

export const emptyList = { status: 200, body: { items: [], next_cursor: null } };

export const signedInRoutes: Record<string, Handler | Reply> = {
  'GET /api/v1/me': { status: 200, body: SESSION },
  'GET /api/v1/hosts?limit=500': emptyList,
  'GET /api/v1/containers?limit=500': emptyList,
  'GET /api/v1/overview/pressure': {
    status: 200,
    body: { generated_at: 0, window_seconds: 300, hosts: [], containers: [] },
  },
};

export const anonymousRoutes = (setupRequired: boolean): Record<string, Handler | Reply> => ({
  'GET /api/v1/me': apiError(
    401,
    'AUTH-DENY-003',
    'You must be signed in to do this.',
    'Sign in and try again.',
  ),
  'GET /api/v1/setup/status': { status: 200, body: { setup_required: setupRequired } },
});
