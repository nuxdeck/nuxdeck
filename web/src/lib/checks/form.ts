// SPDX-License-Identifier: AGPL-3.0-only

import type { Check, CheckAuth, CheckHeader, CheckInput, CheckType } from '../api/client';

// The limits below mirror internal/server/checks/validate.go and pkg/probe. The server stays the
// authority; this only saves a round trip and puts the message next to the field.

export const CHECK_TYPES: readonly { id: CheckType; label: string }[] = [
  { id: 'http', label: 'HTTP(S)' },
  { id: 'tcp', label: 'TCP port' },
  { id: 'dns', label: 'DNS record' },
  { id: 'tls', label: 'TLS certificate' },
  { id: 'ping', label: 'Ping (ICMP)' },
];

export const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX'] as const;

export const URL_HINT =
  'Start with http:// or https://. Put credentials in Authentication, not in the URL.';

export const SERVER_RUNNER = 'server';

const FORBIDDEN_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'upgrade',
  'expect',
  'proxy-authorization',
  'proxy-connection',
  'content-encoding',
  'x-forwarded-for',
  'x-forwarded-host',
  'forwarded',
]);

/** A write-only credential in the editor: the value typed now, never the stored one. */
export interface SecretDraft {
  /** The server holds a value already. */
  wasSet: boolean;
  /** A new value typed by the user; empty keeps what is stored. */
  input: string;
  /** The user asked to remove the stored value. */
  clear: boolean;
}

export const newSecret = (wasSet = false): SecretDraft => ({ wasSet, input: '', clear: false });

/** What to send for a secret: a string sets, "" clears, undefined (omitted) keeps. */
export function secretPayload(d: SecretDraft): string | undefined {
  if (d.input !== '') return d.input;
  if (d.clear && d.wasSet) return '';
  return undefined;
}

export interface HeaderDraft {
  name: string;
  secret: boolean;
  value: string;
  secretValue: SecretDraft;
}

export interface CheckForm {
  name: string;
  type: CheckType;
  runner: string;
  interval: string;
  timeout: string;
  retries: string;
  enabled: boolean;
  allowPrivate: boolean;
  http: {
    url: string;
    method: string;
    body: string;
    headers: HeaderDraft[];
    authType: 'none' | 'basic' | 'bearer';
    username: string;
    password: SecretDraft;
    token: SecretDraft;
    expectedStatus: string;
    keyword: string;
    jsonEnabled: boolean;
    jsonPath: string;
    jsonOp: 'exists' | 'equals';
    jsonValue: string;
    verifyTls: boolean;
    maxRedirects: string;
    maxBodyBytes: string;
  };
  tcp: { host: string; port: string };
  dns: { name: string; recordType: string; resolver: string; expected: string };
  tls: { host: string; port: string; serverName: string; warnDays: string; verifyChain: boolean };
  ping: { host: string; count: string };
}

export function emptyForm(): CheckForm {
  return {
    name: '',
    type: 'http',
    runner: SERVER_RUNNER,
    interval: '60',
    timeout: '10',
    retries: '0',
    enabled: true,
    allowPrivate: false,
    http: {
      url: '',
      method: 'GET',
      body: '',
      headers: [],
      authType: 'none',
      username: '',
      password: newSecret(),
      token: newSecret(),
      expectedStatus: '',
      keyword: '',
      jsonEnabled: false,
      jsonPath: '',
      jsonOp: 'exists',
      jsonValue: '',
      verifyTls: true,
      maxRedirects: '5',
      maxBodyBytes: '65536',
    },
    tcp: { host: '', port: '' },
    dns: { name: '', recordType: 'A', resolver: '', expected: '' },
    tls: { host: '', port: '443', serverName: '', warnDays: '14', verifyChain: true },
    ping: { host: '', count: '3' },
  };
}

/** Fills the editor from a stored check. Secret values are not in the response, only whether they are set. */
export function formFromCheck(c: Check): CheckForm {
  const f = emptyForm();
  f.name = c.name;
  f.type = c.type;
  f.runner = c.runner || SERVER_RUNNER;
  f.interval = String(c.interval_s);
  f.timeout = String(c.timeout_s);
  f.retries = String(c.retries);
  f.enabled = c.enabled;
  f.allowPrivate = c.allow_private;
  const h = c.http;
  if (h) {
    f.http.url = h.url;
    f.http.method = h.method || 'GET';
    f.http.body = h.body ?? '';
    f.http.headers = (h.headers ?? []).map((x) => ({
      name: x.name,
      secret: !!x.secret,
      value: x.secret ? '' : (x.value ?? ''),
      secretValue: newSecret(isSet(x.secret_value)),
    }));
    f.http.authType = h.auth?.type ?? 'none';
    f.http.username = h.auth?.username ?? '';
    f.http.password = newSecret(isSet(h.auth?.password));
    f.http.token = newSecret(isSet(h.auth?.token));
    f.http.expectedStatus = (h.expected_status ?? []).join(', ');
    f.http.keyword = h.keyword ?? '';
    if (h.json) {
      f.http.jsonEnabled = true;
      f.http.jsonPath = h.json.path;
      f.http.jsonOp = h.json.op;
      f.http.jsonValue = h.json.value ?? '';
    }
    f.http.verifyTls = h.verify_tls ?? true;
    f.http.maxRedirects = String(h.max_redirects ?? 5);
    f.http.maxBodyBytes = String(h.max_body_bytes ?? 65536);
  }
  if (c.tcp) f.tcp = { host: c.tcp.host, port: String(c.tcp.port) };
  if (c.dns) {
    f.dns = {
      name: c.dns.name,
      recordType: c.dns.record_type,
      resolver: c.dns.resolver ?? '',
      expected: (c.dns.expected ?? []).join('\n'),
    };
  }
  if (c.tls) {
    f.tls = {
      host: c.tls.host,
      port: String(c.tls.port ?? 443),
      serverName: c.tls.server_name ?? '',
      warnDays: String(c.tls.warn_days ?? 14),
      verifyChain: c.tls.verify_chain ?? true,
    };
  }
  if (c.ping) f.ping = { host: c.ping.host, count: String(c.ping.count ?? 3) };
  return f;
}

function isSet(v: unknown): boolean {
  return typeof v === 'object' && v !== null && (v as { set?: unknown }).set === true;
}

const INT = /^\d+$/;

/** A whole number from a text field, or NaN. */
export function toInt(s: string): number {
  const t = s.trim();
  return INT.test(t) ? Number(t) : NaN;
}

const inRange = (n: number, lo: number, hi: number) => Number.isInteger(n) && n >= lo && n <= hi;

const HEADER_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const HOST_LABEL = /^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*$/;

/** An IP literal or a DNS name, without scheme, port, path or spaces. */
export function validHost(h: string): boolean {
  if (h === '' || h.length > 253) return false;
  if (IPV4.test(h) || (IPV6.test(h) && h.split(':').length >= 3)) return true;
  return h
    .replace(/\.$/, '')
    .split('.')
    .every((l) => HOST_LABEL.test(l));
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;
const PRINTABLE_WITH_SPACE = /^[\t -~]*$/;
const PRINTABLE_NO_SPACE = /^[!-~]*$/;

const hasControl = (s: string) => CONTROL.test(s);

export type FormErrors = Record<string, string>;

/** Checks the form; keys are the field paths the server reports, so both sources land on the same input. */
export function validate(f: CheckForm): FormErrors {
  const e: FormErrors = {};
  const name = f.name.trim();
  if (name === '' || [...name].length > 100 || hasControl(name)) {
    e.name = 'Use 1 to 100 characters without control characters.';
  }
  const interval = toInt(f.interval);
  if (!inRange(interval, 20, 86400)) e.interval_s = 'Use 20 seconds to 24 hours (20 to 86400).';
  const timeout = toInt(f.timeout);
  if (!inRange(timeout, 1, 60) || (inRange(interval, 20, 86400) && timeout >= interval)) {
    e.timeout_s = 'Use 1 to 60 seconds, shorter than the interval.';
  }
  if (!inRange(toInt(f.retries), 0, 5)) e.retries = 'Use 0 to 5.';
  if (f.runner === '') e.runner = 'Choose where the check runs.';

  switch (f.type) {
    case 'http':
      validateHttp(f, e);
      break;
    case 'tcp':
      hostPort(e, 'tcp.host', f.tcp.host, 'tcp.port', f.tcp.port);
      break;
    case 'dns':
      validateDns(f, e);
      break;
    case 'tls': {
      if (!inRange(toInt(f.tls.warnDays), 0, 365)) e['tls.warn_days'] = 'Use 0 to 365.';
      if (f.tls.serverName.trim() !== '' && !validHost(f.tls.serverName.trim())) {
        e['tls.server_name'] = 'Use a host name.';
      }
      hostPort(e, 'tls.host', f.tls.host, 'tls.port', f.tls.port);
      break;
    }
    case 'ping':
      if (!inRange(toInt(f.ping.count), 1, 5)) e['ping.count'] = 'Use 1 to 5.';
      hostPort(e, 'ping.host', f.ping.host);
      break;
  }
  return e;
}

function hostPort(e: FormErrors, hostKey: string, host: string, portKey?: string, port = ''): void {
  if (!validHost(host.trim())) {
    e[hostKey] = 'Use a host name or IP address, without scheme, port or path.';
  }
  if (portKey && !inRange(toInt(port), 1, 65535)) e[portKey] = 'Use 1 to 65535.';
}

function validateDns(f: CheckForm, e: FormErrors): void {
  const d = f.dns;
  if (!validHost(d.name.trim())) e['dns.name'] = 'Use a DNS name.';
  const resolver = d.resolver.trim();
  if (resolver !== '') {
    const at = resolver.lastIndexOf(':');
    const host = at > 0 ? resolver.slice(0, at).replace(/^\[(.*)\]$/, '$1') : '';
    if (!validHost(host) || !inRange(toInt(resolver.slice(at + 1)), 1, 65535)) {
      e['dns.resolver'] = 'Use host:port, for example 9.9.9.9:53.';
    }
  }
  const expected = expectedValues(d.expected);
  if (expected.length > 10) e['dns.expected'] = 'Use at most 10 values.';
  else if (expected.some((v) => v.length > 255 || hasControl(v))) {
    e['dns.expected'] = 'Use 1 to 255 characters per value.';
  }
}

/** One expected DNS value per line; blank lines are ignored. */
export function expectedValues(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

/** "200, 204" -> [200, 204]; anything that is not a code becomes NaN so validation can reject it. */
export function statusCodes(text: string): number[] {
  return text
    .split(/[\s,]+/)
    .filter((t) => t !== '')
    .map(toInt);
}

function validateHttp(f: CheckForm, e: FormErrors): void {
  const h = f.http;
  const url = h.url.trim();
  if (url.length > 2048 || /\s/.test(url) || hasControl(url)) {
    e['http.url'] = 'Use a URL of at most 2048 characters without spaces or control characters.';
  } else {
    let u: URL | null = null;
    try {
      u = new URL(url);
    } catch {
      /* reported below */
    }
    if (!u || u.host === '') e['http.url'] = 'Use an absolute http:// or https:// URL.';
    else if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      e['http.url'] = 'Only http and https URLs are allowed.';
    } else if (u.username !== '' || u.password !== '') {
      e['http.url'] = 'Remove the user name and password from the URL; use the auth setting.';
    }
  }
  if (!(HTTP_METHODS as readonly string[]).includes(h.method)) {
    e['http.method'] = 'Use GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS.';
  }
  if (h.body.length > 4096) e['http.body'] = 'Use at most 4096 characters.';
  else if (h.body !== '' && (h.method === 'GET' || h.method === 'HEAD')) {
    e['http.body'] = 'GET and HEAD requests carry no body.';
  }

  if (h.headers.length > 20) e['http.headers'] = 'Use at most 20 headers.';
  const seen = new Set<string>();
  h.headers.forEach((d, i) => {
    const key = `http.headers[${i}]`;
    const lower = d.name.toLowerCase();
    if (!HEADER_NAME.test(d.name)) {
      e[`${key}.name`] = 'Use letters, digits and hyphens, up to 64 characters.';
    } else if (FORBIDDEN_HEADERS.has(lower) || lower.startsWith('proxy-')) {
      e[`${key}.name`] = 'This header is set by the checker and cannot be overridden.';
    } else if (lower === 'authorization' && h.authType !== 'none') {
      e[`${key}.name`] = 'Authorization is set by the auth setting.';
    } else if (seen.has(lower)) {
      e[`${key}.name`] = 'Header names must be unique.';
    }
    seen.add(lower);
    const value = d.secret ? d.secretValue.input : d.value;
    if (value.length > 1024 || !PRINTABLE_WITH_SPACE.test(value)) {
      e[`${key}.${d.secret ? 'secret_value' : 'value'}`] =
        'Use printable ASCII, up to 1024 characters.';
    }
  });

  if (h.authType === 'basic') {
    if (h.username === '' || h.username.length > 128 || h.username.includes(':')) {
      e['http.auth.username'] = 'Use 1 to 128 characters without a colon.';
    }
    if (h.password.input.length > 256 || hasControl(h.password.input)) {
      e['http.auth.password'] = 'Use at most 256 characters.';
    }
  } else if (h.authType === 'bearer') {
    const t = h.token.input;
    if (t.length > 2048 || !PRINTABLE_NO_SPACE.test(t)) {
      e['http.auth.token'] = 'Use printable ASCII without spaces, up to 2048 characters.';
    }
  }

  const codes = statusCodes(h.expectedStatus);
  if (codes.length > 20) e['http.expected_status'] = 'Use at most 20 codes.';
  else if (codes.some((c) => !inRange(c, 100, 599))) {
    e['http.expected_status'] = 'Use codes from 100 to 599, separated by commas.';
  }
  if (h.keyword.length > 256 || hasControl(h.keyword)) {
    e['http.keyword'] = 'Use at most 256 characters.';
  }
  if (h.jsonEnabled) {
    if (h.jsonPath.trim() === '' || /\s/.test(h.jsonPath.trim())) {
      e['http.json.path'] = 'Use a path such as a.b[0].c.';
    }
    if (h.jsonOp === 'exists' && h.jsonValue !== '') {
      e['http.json.value'] = 'Give a value of at most 256 characters only with equals.';
    } else if (h.jsonValue.length > 256 || hasControl(h.jsonValue)) {
      e['http.json.value'] = 'Give a value of at most 256 characters only with equals.';
    }
  }
  if (!inRange(toInt(h.maxRedirects), 0, 10)) e['http.max_redirects'] = 'Use 0 to 10.';
  if (!inRange(toInt(h.maxBodyBytes), 1, 1_048_576)) {
    e['http.max_body_bytes'] = 'Use 1 to 1048576.';
  }
}

function headerPayload(d: HeaderDraft): CheckHeader {
  if (!d.secret) return { name: d.name, value: d.value };
  const sv = secretPayload(d.secretValue);
  return sv === undefined
    ? { name: d.name, secret: true }
    : { name: d.name, secret: true, secret_value: sv };
}

function authPayload(f: CheckForm): CheckAuth | undefined {
  const h = f.http;
  if (h.authType === 'basic') {
    const pw = secretPayload(h.password);
    return pw === undefined
      ? { type: 'basic', username: h.username }
      : { type: 'basic', username: h.username, password: pw };
  }
  if (h.authType === 'bearer') {
    const t = secretPayload(h.token);
    return t === undefined ? { type: 'bearer' } : { type: 'bearer', token: t };
  }
  return undefined;
}

/** Builds the request body. Call only on a form that passed `validate`. */
export function toInput(f: CheckForm): CheckInput {
  const out: CheckInput = {
    name: f.name.trim(),
    type: f.type,
    runner: f.runner,
    interval_s: toInt(f.interval),
    timeout_s: toInt(f.timeout),
    retries: toInt(f.retries),
    enabled: f.enabled,
    allow_private: f.allowPrivate,
  };
  switch (f.type) {
    case 'http': {
      const h = f.http;
      const codes = statusCodes(h.expectedStatus);
      const auth = authPayload(f);
      out.http = {
        url: h.url.trim(),
        method: h.method,
        ...(h.body !== '' ? { body: h.body } : {}),
        ...(h.headers.length > 0 ? { headers: h.headers.map(headerPayload) } : {}),
        ...(auth ? { auth } : {}),
        ...(codes.length > 0 ? { expected_status: codes } : {}),
        ...(h.keyword !== '' ? { keyword: h.keyword } : {}),
        ...(h.jsonEnabled
          ? {
              json: {
                path: h.jsonPath.trim(),
                op: h.jsonOp,
                ...(h.jsonOp === 'equals' ? { value: h.jsonValue } : {}),
              },
            }
          : {}),
        verify_tls: h.verifyTls,
        max_redirects: toInt(h.maxRedirects),
        max_body_bytes: toInt(h.maxBodyBytes),
      };
      break;
    }
    case 'tcp':
      out.tcp = { host: f.tcp.host.trim(), port: toInt(f.tcp.port) };
      break;
    case 'dns': {
      const expected = expectedValues(f.dns.expected);
      out.dns = {
        name: f.dns.name.trim(),
        record_type: f.dns.recordType,
        ...(f.dns.resolver.trim() !== '' ? { resolver: f.dns.resolver.trim() } : {}),
        ...(expected.length > 0 ? { expected } : {}),
      };
      break;
    }
    case 'tls':
      out.tls = {
        host: f.tls.host.trim(),
        port: toInt(f.tls.port),
        ...(f.tls.serverName.trim() !== '' ? { server_name: f.tls.serverName.trim() } : {}),
        warn_days: toInt(f.tls.warnDays),
        verify_chain: f.tls.verifyChain,
      };
      break;
    case 'ping':
      out.ping = { host: f.ping.host.trim(), count: toInt(f.ping.count) };
      break;
  }
  return out;
}

/** The form field whose input carries the error for a server field path, for focus and display. */
export function fieldId(path: string): string {
  return `chk-${path.replace(/[^A-Za-z0-9]+/g, '-').replace(/-$/, '')}`;
}
