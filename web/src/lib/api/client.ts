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
  tags: Record<string, string>;
  /** Identifies the owner and tags; send it back in If-Match when changing them. */
  etag: string;
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
  owner: string;
  tags: Record<string, string>;
  etag: string;
  restart_count: number;
  created_at: string | null;
  gone_at: string | null;
}

export interface SearchHit {
  type: 'host' | 'container';
  id: string;
  name: string;
  status: string;
  /** The host's name, for containers. */
  host?: string;
  match: 'name' | 'tag' | 'ip';
  detail: string;
}

export type ItemKind = 'hosts' | 'containers';

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

/** One line of a metrics query: points are [unix_ms, value]; counters arrive as per-second rates. */
export interface MetricSeries {
  metric: string;
  labels: Record<string, string>;
  points: [number, number][];
}

export interface MetricsResult {
  resolution: 'full' | '5m';
  kind: 'gauge' | 'rate';
  unit: string;
  step_seconds: number;
  from: number;
  to: number;
  series: MetricSeries[];
}

export interface MetricsQuery {
  /** Host or container ID. */
  target: string;
  metric: string;
  /** Unix milliseconds. */
  from: number;
  to: number;
  /** Seconds per point; the server decimates to it. */
  step?: number;
  /** Exact label filters, at most four. */
  labels?: Record<string, string>;
}

export interface Pressure {
  id: string;
  name: string;
  host_id?: string;
  cpu_percent: number | null;
  memory_percent: number | null;
  disk_percent: number | null;
  score: number | null;
  rank: Record<string, number>;
}

export interface PressureReport {
  generated_at: number;
  window_seconds: number;
  hosts: Pressure[];
  containers: Pressure[];
}

export const MAX_LABEL_FILTERS = 4;

/** The query string of GET /metrics/query; label filters are sorted so equal queries give equal URLs. */
export function metricsQueryString(q: MetricsQuery): string {
  const labels = Object.entries(q.labels ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (labels.length > MAX_LABEL_FILTERS) {
    throw new RangeError(`at most ${MAX_LABEL_FILTERS} label filters are allowed`);
  }
  const p = new URLSearchParams({
    target: q.target,
    metric: q.metric,
    from: String(Math.trunc(q.from)),
    to: String(Math.trunc(q.to)),
  });
  if (q.step !== undefined) p.set('step', String(Math.max(1, Math.ceil(q.step))));
  for (const [k, v] of labels) p.append('label', `${k}:${v}`);
  return p.toString();
}

const NETWORK_ERROR: Omit<ApiError, 'status'> = {
  code: 'NETWORK',
  message: 'Could not reach the server.',
  hint: 'Check your connection and that nuxd is running, then try again.',
};

let csrfToken = '';

async function request<T>(
  method: 'GET' | 'POST' | 'PUT',
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
  signal?: AbortSignal,
): Promise<T> {
  const headers: Record<string, string> = { ...extraHeaders };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      signal,
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
  /** Replaces all tags of an item. `etag` is the one the item carried when the reader loaded it. */
  putTags: (kind: ItemKind, id: string, tags: Record<string, string>, etag: string) =>
    request<Host | Container>(
      'PUT',
      `/items/${kind}/${encodeURIComponent(id)}/tags`,
      { tags },
      { 'If-Match': etag },
    ),
  putOwner: (kind: ItemKind, id: string, owner: string, etag: string) =>
    request<Host | Container>(
      'PUT',
      `/items/${kind}/${encodeURIComponent(id)}/owner`,
      { owner },
      { 'If-Match': etag },
    ),
  search: (q: string, signal?: AbortSignal) =>
    request<{ items: SearchHit[] }>(
      'GET',
      `/search?q=${encodeURIComponent(q)}`,
      undefined,
      {},
      signal,
    ).then((r) => r.items),
  metricsQuery: (q: MetricsQuery, signal?: AbortSignal) =>
    request<MetricsResult>('GET', `/metrics/query?${metricsQueryString(q)}`, undefined, {}, signal),
  pressure: (signal?: AbortSignal) =>
    request<PressureReport>('GET', '/overview/pressure', undefined, {}, signal),
  createEnrollmentToken: () => request<EnrollmentToken>('POST', '/agents/tokens', {}),
  openEvents,
  logout: async () => {
    await request<void>('POST', '/auth/logout');
    csrfToken = '';
  },
};

/** The same-origin WebSocket URL of the log stream (https becomes wss). */
export function logSocketUrl(query: string): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${window.location.host}/api/v1/logs/stream?${query}`;
}

/**
 * A failed WebSocket handshake gives the browser no body, so one plain request to the same URL
 * recovers the JSON error. Resolves to the error, or null when the server shows no refusal.
 */
export async function probeLogStream(query: string): Promise<ApiError | null> {
  try {
    await request<unknown>('GET', `/logs/stream?${query}`);
    return null;
  } catch (e) {
    return e instanceof ApiRequestError ? e.error : null;
  }
}
