// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import type { Check } from '../api/client';
import {
  emptyForm,
  formFromCheck,
  newSecret,
  secretPayload,
  toInput,
  validate,
  validHost,
  type CheckForm,
} from './form';
import { buildResponseSeries, formatUptime, recentResults } from './results';

function valid(patch: (f: CheckForm) => void): CheckForm {
  const f = emptyForm();
  f.name = 'Site';
  f.http.url = 'https://example.com/health';
  patch(f);
  return f;
}

describe('check form validation (UPT-3)', () => {
  it('accepts a minimal HTTP check', () => {
    expect(validate(valid(() => {}))).toEqual({});
  });

  it('checks the common limits', () => {
    const e = validate(
      valid((f) => {
        f.name = '  ';
        f.interval = '19';
        f.timeout = '61';
        f.retries = '6';
      }),
    );
    expect(Object.keys(e).sort()).toEqual(['interval_s', 'name', 'retries', 'timeout_s']);
    expect(validate(valid((f) => ((f.interval = '30'), (f.timeout = '30'))))).toHaveProperty(
      'timeout_s',
    );
    expect(validate(valid((f) => (f.interval = '86401')))).toHaveProperty('interval_s');
    expect(validate(valid((f) => (f.interval = '1e3')))).toHaveProperty('interval_s');
  });

  it('checks HTTP fields', () => {
    const bad = (patch: (f: CheckForm) => void) => Object.keys(validate(valid(patch)));
    expect(bad((f) => (f.http.url = 'ftp://example.com'))).toContain('http.url');
    expect(bad((f) => (f.http.url = 'example.com'))).toContain('http.url');
    expect(bad((f) => (f.http.url = 'https://u:p@example.com/'))).toContain('http.url');
    expect(bad((f) => (f.http.url = 'https://exa mple.com'))).toContain('http.url');
    expect(bad((f) => (f.http.body = 'x'))).toContain('http.body');
    expect(bad((f) => (f.http.expectedStatus = '200, 99'))).toContain('http.expected_status');
    expect(bad((f) => (f.http.maxRedirects = '11'))).toContain('http.max_redirects');
    expect(bad((f) => (f.http.maxBodyBytes = '1048577'))).toContain('http.max_body_bytes');
    expect(
      bad((f) => {
        f.http.jsonEnabled = true;
        f.http.jsonPath = '';
      }),
    ).toContain('http.json.path');
    expect(
      bad((f) => {
        f.http.jsonEnabled = true;
        f.http.jsonPath = 'a.b';
        f.http.jsonValue = 'x';
      }),
    ).toContain('http.json.value');
  });

  it('checks headers and authentication', () => {
    const row = (name: string, value = 'v') => ({
      name,
      secret: false,
      value,
      secretValue: newSecret(),
    });
    const bad = (patch: (f: CheckForm) => void) => validate(valid(patch));
    expect(bad((f) => f.http.headers.push(row('Host')))).toHaveProperty('http.headers[0].name');
    expect(bad((f) => f.http.headers.push(row('X A')))).toHaveProperty('http.headers[0].name');
    expect(bad((f) => f.http.headers.push(row('X-A'), row('x-a')))).toHaveProperty(
      'http.headers[1].name',
    );
    expect(bad((f) => f.http.headers.push(row('X-A', 'é')))).toHaveProperty(
      'http.headers[0].value',
    );
    expect(
      bad((f) => {
        f.http.authType = 'basic';
        f.http.username = 'a:b';
      }),
    ).toHaveProperty('http.auth.username');
    expect(
      bad((f) => {
        f.http.authType = 'bearer';
        f.http.token.input = 'has space';
      }),
    ).toHaveProperty('http.auth.token');
    expect(
      bad((f) => {
        f.http.authType = 'bearer';
        f.http.headers.push(row('Authorization'));
      }),
    ).toHaveProperty('http.headers[0].name');
  });

  it('checks TCP, DNS, TLS and ping fields', () => {
    const tcp = emptyForm();
    tcp.name = 'db';
    tcp.type = 'tcp';
    expect(Object.keys(validate(tcp)).sort()).toEqual(['tcp.host', 'tcp.port']);
    tcp.tcp = { host: 'db.internal', port: '70000' };
    expect(Object.keys(validate(tcp))).toEqual(['tcp.port']);
    tcp.tcp.port = '5432';
    expect(validate(tcp)).toEqual({});

    const dns = emptyForm();
    dns.name = 'dns';
    dns.type = 'dns';
    dns.dns = { name: 'example.com', recordType: 'A', resolver: '9.9.9.9', expected: '' };
    expect(validate(dns)).toHaveProperty('dns.resolver');
    dns.dns.resolver = '9.9.9.9:53';
    dns.dns.expected = Array.from({ length: 11 }, (_, i) => `1.1.1.${i}`).join('\n');
    expect(validate(dns)).toHaveProperty('dns.expected');
    dns.dns.expected = '1.1.1.1';
    expect(validate(dns)).toEqual({});

    const tls = emptyForm();
    tls.name = 'cert';
    tls.type = 'tls';
    tls.tls.host = 'example.com';
    tls.tls.warnDays = '366';
    tls.tls.serverName = 'bad name';
    expect(Object.keys(validate(tls)).sort()).toEqual(['tls.server_name', 'tls.warn_days']);

    const ping = emptyForm();
    ping.name = 'p';
    ping.type = 'ping';
    ping.ping = { host: 'http://x', count: '6' };
    expect(Object.keys(validate(ping)).sort()).toEqual(['ping.count', 'ping.host']);
  });

  it('recognises host names and addresses', () => {
    for (const ok of ['example.com', 'a_b.example.', '10.0.0.1', '::1', '2001:db8::1'])
      expect(validHost(ok), ok).toBe(true);
    for (const bad of ['', 'a b', 'host:80', 'a/b', '-x.com', 'x'.repeat(254)])
      expect(validHost(bad), bad).toBe(false);
  });
});

describe('secrets are write-only (UPT-3)', () => {
  const stored: Check = {
    id: 'x',
    name: 'API',
    type: 'http',
    runner: 'server',
    interval_s: 60,
    timeout_s: 10,
    retries: 0,
    enabled: true,
    allow_private: false,
    http: {
      url: 'https://example.com/',
      headers: [
        { name: 'X-Api-Key', secret: true, secret_value: { set: true } },
        { name: 'Accept', value: 'text/html' },
      ],
      auth: { type: 'basic', username: 'ada', password: { set: true } },
    },
    created_by: '',
    updated_by: '',
    created_at: '',
    updated_at: '',
    status: {
      state: 'up',
      since: null,
      last_checked: null,
      last_latency_ms: null,
      last_error_code: '',
      last_detail: '',
    },
  };

  it('maps keep, replace and clear to omit, string and the empty string', () => {
    expect(secretPayload({ wasSet: true, input: '', clear: false })).toBeUndefined();
    expect(secretPayload({ wasSet: true, input: 'new', clear: false })).toBe('new');
    expect(secretPayload({ wasSet: true, input: '', clear: true })).toBe('');
    expect(secretPayload({ wasSet: false, input: '', clear: true })).toBeUndefined();
  });

  it('loads a stored secret as "set" with no value and keeps it by omission', () => {
    const f = formFromCheck(stored);
    expect(f.http.headers[0]!.secretValue).toEqual({ wasSet: true, input: '', clear: false });
    expect(f.http.password.wasSet).toBe(true);
    const body = toInput(f);
    expect(body.http!.headers![0]).toEqual({ name: 'X-Api-Key', secret: true });
    expect(body.http!.auth).toEqual({ type: 'basic', username: 'ada' });
    expect(JSON.stringify(body)).not.toContain('secret_value');
  });

  it('sends a replacement and a clear exactly', () => {
    const f = formFromCheck(stored);
    f.http.headers[0]!.secretValue.input = 'k-123';
    f.http.password.clear = true;
    const body = toInput(f);
    expect(body.http!.headers![0]).toEqual({
      name: 'X-Api-Key',
      secret: true,
      secret_value: 'k-123',
    });
    expect(body.http!.auth).toEqual({ type: 'basic', username: 'ada', password: '' });
  });
});

describe('response data (UPT-4)', () => {
  const at = (s: number) => new Date(Date.UTC(2026, 9, 28, 12, 0, s)).toISOString();
  const rows = [
    { ts: at(30), status: 'up', latency_ms: 30, error_code: '', detail: '' },
    { ts: at(20), status: 'down', latency_ms: 0, error_code: 'CHK-TCP-001', detail: 'refused' },
    { ts: at(10), status: 'up', latency_ms: 10, error_code: '', detail: '' },
    { ts: at(0), status: 'up', latency_ms: 99, error_code: '', detail: '' },
  ];

  it('builds an ascending latency series from successful runs inside the window', () => {
    const from = Date.parse(at(5));
    const [s] = buildResponseSeries(rows, from, Date.parse(at(60)));
    expect(s!.points).toEqual([
      [Date.parse(at(10)), 10],
      [Date.parse(at(30)), 30],
    ]);
  });

  it('returns an empty series for no results', () => {
    expect(buildResponseSeries([], 0, 1)[0]!.points).toEqual([]);
  });

  it('keeps the newest results, oldest first', () => {
    expect(recentResults(rows, 2).map((r) => r.ts)).toEqual([at(20), at(30)]);
  });

  it('formats a missing uptime as no data', () => {
    expect(formatUptime(null)).toBe('No data');
    expect(formatUptime(99.9)).toBe('99.9%');
    expect(formatUptime(100)).toBe('100%');
    expect(formatUptime(99.12345)).toBe('99.12%');
  });
});
