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

export interface Host {
  id: string;
  agent_id: string;
  hostname: string;
  os: string;
  distro: string;
  kernel: string;
  arch: string;
  cpu_count: number;
  memory_bytes: number;
  facts: Record<string, string>;
  owner: string;
  status: 'online' | 'offline' | 'gone';
  first_seen_at: string;
  last_seen_at: string;
  gone_at: string | null;
}

export interface Port {
  host_ip: string;
  host_port: number;
  container_port: number;
  protocol: string;
}

export interface Container {
  id: string;
  host_id: string;
  runtime: 'docker' | 'podman';
  runtime_id: string;
  name: string;
  image: string;
  state: string;
  ports: Port[];
  labels: Record<string, string>;
  restart_count: number;
  created_at: string | null;
  gone_at: string | null;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface EnrollmentToken {
  id: string;
  token: string;
  expires_at: string;
}

/** The change types the server pushes on /events (internal/server/inventory). */
export type EventType =
  | 'host.created'
  | 'host.updated'
  | 'container.created'
  | 'container.updated'
  | 'container.removed'
  | 'resync';

export interface ServerEvent {
  type: EventType;
  at: string;
  item?: Host | Container;
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

const PAGE_SIZE = 500;

/** Reads every page of a list endpoint. */
async function all<T>(path: string): Promise<T[]> {
  const items: T[] = [];
  let cursor: string | null = null;
  do {
    const query: string = `?limit=${PAGE_SIZE}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
    const page: Page<T> = await request<Page<T>>('GET', `${path}${query}`);
    items.push(...page.items);
    cursor = page.next_cursor;
  } while (cursor);
  return items;
}

const EVENT_TYPES: EventType[] = [
  'host.created',
  'host.updated',
  'container.created',
  'container.updated',
  'container.removed',
  'resync',
];

export interface EventHandlers {
  onEvent: (event: ServerEvent) => void;
  /** The stream is open: on the first call and after every automatic reconnect. */
  onOpen: () => void;
  /** The stream broke. `fatal` means the browser gave up (for example the session ended). */
  onError: (fatal: boolean) => void;
}

/** Opens the live change stream and returns a function that closes it. */
function openEvents(h: EventHandlers): () => void {
  if (typeof EventSource === 'undefined') {
    queueMicrotask(() => h.onError(true)); // no live updates in this environment; pages say so
    return () => {};
  }
  const source = new EventSource('/api/v1/events');
  source.onopen = () => h.onOpen();
  source.onerror = () => h.onError(source.readyState === EventSource.CLOSED);
  for (const type of EVENT_TYPES) {
    source.addEventListener(type, (e) => {
      try {
        h.onEvent(JSON.parse((e as MessageEvent<string>).data) as ServerEvent);
      } catch {
        h.onEvent({ type: 'resync', at: new Date().toISOString() }); // an unreadable event: reload rather than guess
      }
    });
  }
  return () => source.close();
}

export const api = {
  setupStatus: () => request<{ setup_required: boolean }>('GET', '/setup/status'),
  completeSetup: async (r: SetupRequest) =>
    remember(await request<Session>('POST', '/setup/admin', r)),
  login: async (email: string, password: string) =>
    remember(await request<Session>('POST', '/auth/login', { email, password })),
  me: async () => remember(await request<Session>('GET', '/me')),
  hosts: () => all<Host>('/hosts'),
  host: (id: string) => request<Host>('GET', `/hosts/${encodeURIComponent(id)}`),
  containers: () => all<Container>('/containers'),
  container: (id: string) => request<Container>('GET', `/containers/${encodeURIComponent(id)}`),
  createEnrollmentToken: () => request<EnrollmentToken>('POST', '/agents/tokens', {}),
  openEvents,
  logout: async () => {
    await request<void>('POST', '/auth/logout');
    csrfToken = '';
  },
};
