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
  /** Seconds to wait before retrying, from a Retry-After header (429 responses). */
  retryAfter?: number;
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

export type CheckType = 'http' | 'tcp' | 'dns' | 'tls' | 'ping';
export type CheckState = 'up' | 'down' | 'unknown';

/** A credential as the server returns it: whether one is stored, never the value. */
export interface SecretState {
  set: boolean;
}

/** What may be sent for a secret: a string sets it, "" clears it, absent or {set:true} keeps it. */
export type SecretInput = string | SecretState | null | undefined;

export interface CheckHeader {
  name: string;
  value?: string;
  secret?: boolean;
  secret_value?: SecretInput;
}

export interface CheckAuth {
  type: 'none' | 'basic' | 'bearer';
  username?: string;
  password?: SecretInput;
  token?: SecretInput;
}

export interface HttpSpec {
  url: string;
  method?: string;
  headers?: CheckHeader[];
  body?: string;
  auth?: CheckAuth | null;
  expected_status?: number[];
  keyword?: string;
  json?: { path: string; op: 'exists' | 'equals'; value?: string } | null;
  verify_tls?: boolean;
  max_redirects?: number;
  max_body_bytes?: number;
}

export interface CheckStatus {
  state: CheckState;
  since: string | null;
  last_checked: string | null;
  last_latency_ms: number | null;
  last_error_code: string;
  last_detail: string;
}

/** The body of POST and PUT /checks; exactly the section for `type` is present. */
export interface CheckInput {
  name: string;
  type: CheckType;
  runner: string;
  interval_s: number;
  timeout_s: number;
  retries: number;
  enabled: boolean;
  allow_private: boolean;
  http?: HttpSpec;
  tcp?: { host: string; port: number };
  dns?: { name: string; record_type: string; resolver?: string; expected?: string[] };
  tls?: {
    host: string;
    port?: number;
    server_name?: string;
    warn_days?: number;
    verify_chain?: boolean;
  };
  ping?: { host: string; count?: number };
}

export interface Check extends Omit<CheckInput, 'http'> {
  id: string;
  http?: HttpSpec;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
  status: CheckStatus;
}

export interface CheckResult {
  ts: string;
  status: string;
  latency_ms: number;
  error_code: string;
  detail: string;
}

export interface CheckUptime {
  '24h': number | null;
  '7d': number | null;
  '30d': number | null;
  '90d': number | null;
}

/** A check together with the ETag it was read with. */
export interface CheckWithEtag {
  check: Check;
  etag: string;
}

/** One named group of checks on a status page. */
export interface StatusComponent {
  id?: string;
  name: string;
  check_ids: string[];
}

/** The editable part of a status page. `slug` is fixed once the page exists. */
export interface StatusPageInput {
  slug: string;
  title: string;
  description: string;
  published: boolean;
  components: StatusComponent[];
}

export interface StatusPage extends StatusPageInput {
  id: string;
  created_at: string;
  updated_at: string;
}

export type IncidentStatus = 'investigating' | 'identified' | 'monitoring' | 'resolved';
export type IncidentImpact = 'none' | 'minor' | 'major';

export interface IncidentUpdate {
  status: IncidentStatus;
  body: string;
  created_by: string;
  at: string;
}

export interface Incident {
  id: string;
  page_id: string;
  title: string;
  body: string;
  status: IncidentStatus;
  impact: IncidentImpact;
  created_by: string;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  updates: IncidentUpdate[];
}

export interface IncidentInput {
  title: string;
  body: string;
  status: IncidentStatus;
  impact: IncidentImpact;
}

/** A status page with the ETag it was read with. */
export interface StatusPageWithEtag {
  page: StatusPage;
  etag: string;
}

export type PublicLevel = 'operational' | 'degraded' | 'outage' | 'unknown';

/** What GET /status/{slug}.json returns: the anonymous projection, nothing internal. */
export interface PublicStatus {
  title: string;
  description: string;
  status: PublicLevel;
  generated_at: string;
  components: {
    name: string;
    status: PublicLevel;
    uptime_90d: number | null;
    days: { date: string; status: PublicLevel }[];
  }[];
  incidents: {
    title: string;
    body: string;
    status: IncidentStatus;
    impact: IncidentImpact;
    started_at: string;
    resolved_at: string | null;
    updates: { status: IncidentStatus; body: string; at: string }[];
  }[];
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

// ---- Alerting (ALR-*) ----

export type RuleKind =
  'check_down' | 'host_offline' | 'container_stopped' | 'metric_threshold' | 'tls_expiring';
export type Severity = 'info' | 'warning' | 'critical';
export type AlertState = 'open' | 'acked' | 'resolved';
export type AlertItemType = 'host' | 'container' | 'check';

export interface Selector {
  tags: string[];
  ids: string[];
  severity: string[];
  kinds: string[];
}

export interface RuleInput {
  name: string;
  kind: RuleKind;
  severity: Severity;
  enabled: boolean;
  selector: { tags: string[]; ids: string[] };
  params: Record<string, unknown>;
}

export interface Rule extends RuleInput {
  id: string;
  selector: Selector;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface RuleWithEtag {
  rule: Rule;
  etag: string;
}

export interface AlertItem {
  id: string;
  rule_id: string;
  rule_name: string;
  kind: RuleKind;
  severity: Severity;
  item_type: AlertItemType;
  item_id: string;
  item_name: string;
  summary: string;
  /** Absolute URL from the server; the UI derives its own in-app route instead. */
  link: string;
  state: AlertState;
  opened_at: string;
  acked_by: string;
  acked_at: string | null;
  resolved_at: string | null;
  resolve_reason: string;
  flap_count: number;
  last_notified_at: string | null;
}

export type AlertStateFilter = AlertState | 'active';

export interface AlertQuery {
  state?: AlertStateFilter;
  severity?: string;
  item_id?: string;
  rule_id?: string;
  limit?: number;
}

export type SilenceKind = 'silence' | 'maintenance';

export interface SilenceInput {
  kind: SilenceKind;
  selector: Partial<Selector>;
  starts_at?: string;
  ends_at: string;
  reason: string;
}

export interface Silence {
  id: string;
  kind: SilenceKind;
  selector: Selector;
  starts_at: string;
  ends_at: string;
  reason: string;
  created_by: string;
  created_at: string;
  state: 'scheduled' | 'active' | 'expired';
}

export type ChannelType = 'smtp' | 'slack' | 'teams' | 'discord' | 'telegram' | 'webhook';

export interface ChannelInput {
  name: string;
  type: ChannelType;
  enabled: boolean;
  allow_private: boolean;
  /** Secrets: a string sets, "" clears, omitted keeps; they read back as {"set": true}. */
  config: Record<string, unknown>;
}

export interface Channel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  allow_private: boolean;
  config: Record<string, unknown>;
  last_status: 'never' | 'ok' | 'failed';
  last_error_code: string;
  last_sent_at: string | null;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface ChannelWithEtag {
  channel: Channel;
  etag: string;
}

export interface RouteEntry {
  id?: string;
  selector: { tags: string[]; severity: string[]; kinds: string[] };
  channel_id: string;
  continue: boolean;
}

export interface RouteList {
  routes: RouteEntry[];
  etag: string;
}

const NETWORK_ERROR: Omit<ApiError, 'status'> = {
  code: 'NETWORK',
  message: 'Could not reach the server.',
  hint: 'Check your connection and that nuxd is running, then try again.',
};

let csrfToken = '';

async function request<T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
  signal?: AbortSignal,
  meta?: { etag?: string },
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

  if (meta) meta.etag = response.headers.get('ETag') ?? undefined;
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
      retryAfter: parseRetryAfter(response.headers.get('Retry-After')),
    });
  }
  return payload as T;
}

function parseRetryAfter(value: string | null): number | undefined {
  const n = value === null ? NaN : Number(value);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
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
  checks: () => all<Check>('/checks'),
  check: async (id: string): Promise<CheckWithEtag> => {
    const meta: { etag?: string } = {};
    const check = await request<Check>(
      'GET',
      `/checks/${encodeURIComponent(id)}`,
      undefined,
      {},
      undefined,
      meta,
    );
    return { check, etag: meta.etag ?? '' };
  },
  createCheck: async (input: CheckInput): Promise<CheckWithEtag> => {
    const meta: { etag?: string } = {};
    const check = await request<Check>('POST', '/checks', input, {}, undefined, meta);
    return { check, etag: meta.etag ?? '' };
  },
  /** `etag` is required: the server refuses a replace it cannot tie to the version the editor loaded. */
  updateCheck: async (id: string, input: CheckInput, etag: string): Promise<CheckWithEtag> => {
    const meta: { etag?: string } = {};
    const check = await request<Check>(
      'PUT',
      `/checks/${encodeURIComponent(id)}`,
      input,
      { 'If-Match': etag },
      undefined,
      meta,
    );
    return { check, etag: meta.etag ?? '' };
  },
  deleteCheck: (id: string) => request<void>('DELETE', `/checks/${encodeURIComponent(id)}`),
  runCheck: (id: string) =>
    request<CheckResult>('POST', `/checks/${encodeURIComponent(id)}/run`, {}),
  checkResults: (id: string, limit = 500, cursor?: string | null, signal?: AbortSignal) =>
    request<Page<CheckResult>>(
      'GET',
      `/checks/${encodeURIComponent(id)}/results?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
      undefined,
      {},
      signal,
    ),
  checkUptime: (id: string, signal?: AbortSignal) =>
    request<CheckUptime>('GET', `/checks/${encodeURIComponent(id)}/uptime`, undefined, {}, signal),
  statusPages: () => request<{ items: StatusPage[] }>('GET', '/status-pages').then((r) => r.items),
  statusPage: async (id: string): Promise<StatusPageWithEtag> => {
    const meta: { etag?: string } = {};
    const page = await request<StatusPage>(
      'GET',
      `/status-pages/${encodeURIComponent(id)}`,
      undefined,
      {},
      undefined,
      meta,
    );
    return { page, etag: meta.etag ?? '' };
  },
  createStatusPage: async (input: StatusPageInput): Promise<StatusPageWithEtag> => {
    const meta: { etag?: string } = {};
    const page = await request<StatusPage>('POST', '/status-pages', input, {}, undefined, meta);
    return { page, etag: meta.etag ?? '' };
  },
  /** `etag` is required: the server refuses a replace it cannot tie to the version the editor loaded. */
  updateStatusPage: async (
    id: string,
    input: StatusPageInput,
    etag: string,
  ): Promise<StatusPageWithEtag> => {
    const meta: { etag?: string } = {};
    const page = await request<StatusPage>(
      'PUT',
      `/status-pages/${encodeURIComponent(id)}`,
      input,
      { 'If-Match': etag },
      undefined,
      meta,
    );
    return { page, etag: meta.etag ?? '' };
  },
  deleteStatusPage: (id: string) =>
    request<void>('DELETE', `/status-pages/${encodeURIComponent(id)}`),
  incidents: (pageId: string) =>
    request<{ items: Incident[] }>(
      'GET',
      `/status-pages/${encodeURIComponent(pageId)}/incidents`,
    ).then((r) => r.items),
  createIncident: (pageId: string, input: IncidentInput) =>
    request<Incident>('POST', `/status-pages/${encodeURIComponent(pageId)}/incidents`, input),
  addIncidentUpdate: (
    pageId: string,
    incidentId: string,
    update: { status: IncidentStatus; body: string; impact?: IncidentImpact },
  ) =>
    request<Incident>(
      'POST',
      `/status-pages/${encodeURIComponent(pageId)}/incidents/${encodeURIComponent(incidentId)}/updates`,
      update,
    ),
  resolveIncident: (pageId: string, incidentId: string, body: string) =>
    request<Incident>(
      'POST',
      `/status-pages/${encodeURIComponent(pageId)}/incidents/${encodeURIComponent(incidentId)}/resolve`,
      { body },
    ),
  deleteIncident: (pageId: string, incidentId: string) =>
    request<void>(
      'DELETE',
      `/status-pages/${encodeURIComponent(pageId)}/incidents/${encodeURIComponent(incidentId)}`,
    ),
  /** The public projection, read from the anonymous endpoint exactly as a visitor's browser would. */
  publicStatus: async (slug: string, signal?: AbortSignal): Promise<PublicStatus | null> => {
    let response: Response;
    try {
      response = await fetch(`/status/${encodeURIComponent(slug)}.json`, {
        credentials: 'omit',
        signal,
      });
    } catch {
      throw new ApiRequestError({ status: 0, ...NETWORK_ERROR });
    }
    if (response.status === 404) return null;
    if (!response.ok) {
      throw new ApiRequestError({
        status: response.status,
        code: 'API-INT-001',
        message: 'The public page could not be read.',
        hint: 'Try again.',
      });
    }
    return (await response.json()) as PublicStatus;
  },
  rules: () => all<Rule>('/rules'),
  rule: async (id: string): Promise<RuleWithEtag> => {
    const meta: { etag?: string } = {};
    const rule = await request<Rule>(
      'GET',
      `/rules/${encodeURIComponent(id)}`,
      undefined,
      {},
      undefined,
      meta,
    );
    return { rule, etag: meta.etag ?? '' };
  },
  createRule: (input: RuleInput) => request<Rule>('POST', '/rules', input),
  updateRule: async (id: string, input: RuleInput, etag: string): Promise<RuleWithEtag> => {
    const meta: { etag?: string } = {};
    const rule = await request<Rule>(
      'PUT',
      `/rules/${encodeURIComponent(id)}`,
      input,
      { 'If-Match': etag },
      undefined,
      meta,
    );
    return { rule, etag: meta.etag ?? '' };
  },
  deleteRule: (id: string) => request<void>('DELETE', `/rules/${encodeURIComponent(id)}`),
  alerts: (q: AlertQuery = {}, signal?: AbortSignal) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== '') p.set(k, String(v));
    p.set('limit', String(q.limit ?? 200));
    return request<Page<AlertItem>>('GET', `/alerts?${p.toString()}`, undefined, {}, signal).then(
      (r) => r.items,
    );
  },
  alert: (id: string) => request<AlertItem>('GET', `/alerts/${encodeURIComponent(id)}`),
  ackAlert: (id: string) => request<AlertItem>('POST', `/alerts/${encodeURIComponent(id)}/ack`, {}),
  silences: (activeOnly = false) =>
    request<Page<Silence>>('GET', `/silences?limit=200${activeOnly ? '&active=true' : ''}`).then(
      (r) => r.items,
    ),
  createSilence: (input: SilenceInput) => request<Silence>('POST', '/silences', input),
  deleteSilence: (id: string) => request<void>('DELETE', `/silences/${encodeURIComponent(id)}`),
  channels: () => all<Channel>('/channels'),
  channel: async (id: string): Promise<ChannelWithEtag> => {
    const meta: { etag?: string } = {};
    const channel = await request<Channel>(
      'GET',
      `/channels/${encodeURIComponent(id)}`,
      undefined,
      {},
      undefined,
      meta,
    );
    return { channel, etag: meta.etag ?? '' };
  },
  createChannel: (input: ChannelInput) => request<Channel>('POST', '/channels', input),
  updateChannel: async (
    id: string,
    input: ChannelInput,
    etag: string,
  ): Promise<ChannelWithEtag> => {
    const meta: { etag?: string } = {};
    const channel = await request<Channel>(
      'PUT',
      `/channels/${encodeURIComponent(id)}`,
      input,
      { 'If-Match': etag },
      undefined,
      meta,
    );
    return { channel, etag: meta.etag ?? '' };
  },
  deleteChannel: (id: string) => request<void>('DELETE', `/channels/${encodeURIComponent(id)}`),
  testChannel: (id: string) =>
    request<{ ok: boolean }>('POST', `/channels/${encodeURIComponent(id)}/test`, {}),
  routes: async (): Promise<RouteList> => {
    const meta: { etag?: string } = {};
    const doc = await request<{ routes: RouteEntry[] }>(
      'GET',
      '/routes',
      undefined,
      {},
      undefined,
      meta,
    );
    return { routes: doc.routes ?? [], etag: meta.etag ?? '' };
  },
  replaceRoutes: async (routes: RouteEntry[], etag: string): Promise<RouteList> => {
    const meta: { etag?: string } = {};
    const doc = await request<{ routes: RouteEntry[] }>(
      'PUT',
      '/routes',
      { routes },
      { 'If-Match': etag },
      undefined,
      meta,
    );
    return { routes: doc.routes ?? [], etag: meta.etag ?? '' };
  },
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
