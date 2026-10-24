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
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );
  return calls;
}

export const signedInRoutes: Record<string, Handler | Reply> = {
  'GET /api/v1/me': { status: 200, body: SESSION },
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
