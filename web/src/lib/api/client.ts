// SPDX-License-Identifier: AGPL-3.0-only

// TEMPORARY, hand-written. docs/08-engineering-spec.md requires this client to be
// generated from the OpenAPI document (NUX-40); until that exists this is the only
// file allowed to call fetch, so replacing it is a one-file change.

export interface ApiError {
  status: number;
  code: string;
  message: string;
  hint: string;
  field?: string;
}

export class ApiRequestError extends Error {
  constructor(readonly error: ApiError) {
    super(`${error.code}: ${error.message}`);
  }
}

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

export interface Session {
  user: User;
  csrf_token: string;
}

export interface SetupRequest {
  token: string;
  name: string;
  email: string;
  password: string;
}

const NETWORK_ERROR: Omit<ApiError, 'status'> = {
  code: 'NETWORK',
  message: 'Could not reach the server.',
  hint: 'Check your connection and that nuxd is running, then try again.',
};

let csrfToken = '';

async function request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiRequestError({ status: 0, ...NETWORK_ERROR });
  }

  if (response.status === 204) return undefined as T;
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }
  if (!response.ok) {
    const e = (payload as { error?: Partial<ApiError> } | undefined)?.error;
    throw new ApiRequestError({
      status: response.status,
      code: e?.code ?? 'API-INT-001',
      message: e?.message ?? 'Something went wrong on the server.',
      hint: e?.hint ?? 'Try again.',
      field: e?.field,
    });
  }
  return payload as T;
}

function remember(s: Session): Session {
  csrfToken = s.csrf_token;
  return s;
}

export const api = {
  setupStatus: () => request<{ setup_required: boolean }>('GET', '/setup/status'),
  completeSetup: async (r: SetupRequest) =>
    remember(await request<Session>('POST', '/setup/admin', r)),
  login: async (email: string, password: string) =>
    remember(await request<Session>('POST', '/auth/login', { email, password })),
  me: async () => remember(await request<Session>('GET', '/me')),
  logout: async () => {
    await request<void>('POST', '/auth/logout');
    csrfToken = '';
  },
};
