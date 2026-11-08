// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import type { AlertItem, Channel, Rule, RouteEntry, Silence } from './lib/api/client';
import { ALERT_HINTS } from './lib/alerts/errors';
import { itemRoute, parseIds, tagError } from './lib/alerts/model';
import {
  channelInput,
  emptyChannelForm,
  formFromChannel,
  validateChannel,
} from './lib/alerts/channels';
import { draftFrom, move, routesPayload } from './lib/alerts/routes';
import { emptyRuleForm, formFromRule, ruleInput, validateRule } from './lib/alerts/rules';
import {
  emptySilenceForm,
  itemSilence,
  silenceInput,
  toLocalInput,
  validateSilence,
} from './lib/alerts/silences';
import { resolveRoute, router } from './lib/router.svelte';
import {
  ADMIN,
  apiError,
  fakeServer,
  SESSION,
  signedInRoutes,
  type Call,
  type Handler,
  type Reply,
} from './test-helpers';

const A1 = '01HZ0000000000000000000701';
const A2 = '01HZ0000000000000000000702';
const HOST = '01HZ0000000000000000000801';
const CHECK = '01HZ0000000000000000000802';
const RULE = '01HZ0000000000000000000901';
const CHAN = '01HZ0000000000000000000A01';
const SIL = '01HZ0000000000000000000B01';
const NOW = '2026-10-28T10:00:00Z';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  router.navigate('/');
});

const as = (...roles: string[]): Record<string, Reply> => ({
  'GET /api/v1/me': { status: 200, body: { ...SESSION, user: { ...ADMIN, roles } } },
});

const page = <T>(items: T[]): Reply => ({ status: 200, body: { items, next_cursor: null } });

function alertItem(id: string, extra: Partial<AlertItem> = {}): AlertItem {
  return {
    id,
    rule_id: RULE,
    rule_name: 'Hosts offline',
    kind: 'host_offline',
    severity: 'critical',
    item_type: 'host',
    item_id: HOST,
    item_name: 'db-1',
    summary: 'db-1 is offline',
    link: 'https://nux.example.com/inventory/hosts/x',
    state: 'open',
    opened_at: NOW,
    acked_by: '',
    acked_at: null,
    resolved_at: null,
    resolve_reason: '',
    flap_count: 2,
    last_notified_at: null,
    ...extra,
  };
}

function rule(extra: Partial<Rule> = {}): Rule {
  return {
    id: RULE,
    name: 'Hosts offline',
    kind: 'host_offline',
    severity: 'critical',
    enabled: true,
    selector: { tags: ['env:production'], ids: [], severity: [], kinds: [] },
    params: { for_s: 60 },
    created_by: 'u1',
    updated_by: 'u1',
    created_at: NOW,
    updated_at: NOW,
    ...extra,
  };
}

function channel(extra: Partial<Channel> = {}): Channel {
  return {
    id: CHAN,
    name: 'On-call Slack',
    type: 'slack',
    enabled: true,
    allow_private: false,
    config: { url: { set: true } },
    last_status: 'never',
    last_error_code: '',
    last_sent_at: null,
    created_by: 'u1',
    updated_by: 'u1',
    created_at: NOW,
    updated_at: NOW,
    ...extra,
  };
}

function silence(extra: Partial<Silence> = {}): Silence {
  return {
    id: SIL,
    kind: 'silence',
    selector: { tags: [], ids: [HOST], severity: [], kinds: [] },
    starts_at: NOW,
    ends_at: '2099-01-01T00:00:00Z',
    reason: 'Upgrading db-1',
    created_by: 'u1',
    created_at: NOW,
    state: 'active',
    ...extra,
  };
}

const route = (extra: Partial<RouteEntry> = {}): RouteEntry => ({
  id: 'r1',
  selector: { tags: [], severity: ['critical'], kinds: [] },
  channel_id: CHAN,
  continue: false,
  ...extra,
});

const base = (extra: Record<string, Handler | Reply> = {}) => ({ ...signedInRoutes, ...extra });

async function open(path: string): Promise<{ container: HTMLElement }> {
  router.navigate(path);
  const r = render(App);
  await screen.findByRole('navigation', { name: 'Main' });
  return r;
}

async function violations(container: HTMLElement): Promise<string[]> {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`,
  );
}

const byId = (id: string) => document.getElementById(id) as HTMLInputElement;

describe('rule form (ALR-1)', () => {
  const ok = (patch: Partial<ReturnType<typeof emptyRuleForm>>) => ({
    ...emptyRuleForm(),
    name: 'R',
    ...patch,
  });

  it('accepts the defaults and sends only the for-duration it was given', () => {
    expect(validateRule(ok({}))).toEqual({});
    expect(ruleInput(ok({})).params).toEqual({});
    expect(ruleInput(ok({ forS: '120' })).params).toEqual({ for_s: 120 });
  });

  it('checks the name, the for-duration and the selector', () => {
    const e = validateRule(ok({ name: ' ', forS: '86401', tags: ['bad tag'], ids: 'nope' }));
    expect(Object.keys(e).sort()).toEqual(
      ['name', 'params.for_s', 'selector.ids', 'selector.tags'].sort(),
    );
    expect(validateRule(ok({ forS: '86400' }))).toEqual({});
    expect(validateRule(ok({ forS: '-1' }))['params.for_s']).toBeTruthy();
  });

  it('validates container rules and omits restart params for "stopped"', () => {
    const c = { kind: 'container_stopped' as const };
    expect(validateRule(ok({ ...c, restarts: '1' }))['params.restarts']).toBeTruthy();
    expect(validateRule(ok({ ...c, restarts: '101' }))['params.restarts']).toBeTruthy();
    expect(validateRule(ok({ ...c, windowS: '59' }))['params.window_s']).toBeTruthy();
    expect(validateRule(ok({ ...c, windowS: '3601' }))['params.window_s']).toBeTruthy();
    expect(validateRule(ok({ ...c, restarts: '2', windowS: '60' }))).toEqual({});
    expect(ruleInput(ok({ ...c, mode: 'stopped', restarts: '1' })).params).toEqual({
      mode: 'stopped',
    });
    expect(ruleInput(ok({ ...c, restarts: '5', windowS: '300' })).params).toEqual({
      mode: 'either',
      restarts: 5,
      window_s: 300,
    });
  });

  it('validates metric rules: percent range and disk only on hosts', () => {
    const m = { kind: 'metric_threshold' as const };
    expect(validateRule(ok({ ...m, threshold: '0' }))['params.threshold']).toBeTruthy();
    expect(validateRule(ok({ ...m, threshold: '100.5' }))['params.threshold']).toBeTruthy();
    expect(validateRule(ok({ ...m, threshold: '' }))['params.threshold']).toBeTruthy();
    expect(validateRule(ok({ ...m, threshold: '100' }))).toEqual({});
    expect(
      validateRule(ok({ ...m, target: 'container', metric: 'disk' }))['params.metric'],
    ).toBeTruthy();
    expect(
      ruleInput(ok({ ...m, target: 'host', metric: 'disk', threshold: '85.5' })).params,
    ).toEqual({
      target: 'host',
      metric: 'disk',
      threshold: 85.5,
    });
  });

  it('validates certificate rules', () => {
    const t = { kind: 'tls_expiring' as const };
    expect(validateRule(ok({ ...t, days: '0' }))['params.days']).toBeTruthy();
    expect(validateRule(ok({ ...t, days: '826' }))['params.days']).toBeTruthy();
    expect(ruleInput(ok({ ...t, days: '825' })).params).toEqual({ days: 825 });
  });

  it('round-trips a stored rule into the form and back', () => {
    const r = rule({ kind: 'tls_expiring', params: { days: 30, for_s: 0 } });
    const input = ruleInput(formFromRule(r));
    expect(input).toMatchObject({ kind: 'tls_expiring', params: { days: 30, for_s: 0 } });
    expect(input.selector).toEqual({ tags: ['env:production'], ids: [] });
  });
});

describe('selector helpers', () => {
  it('validates tags like the server', () => {
    expect(tagError('env:production')).toBeNull();
    expect(tagError('env')).toBeNull();
    expect(tagError('env:')).toBeNull();
    expect(tagError('has space:x')).not.toBeNull();
    expect(tagError(':x')).not.toBeNull();
  });
  it('splits item IDs on commas, spaces and lines', () => {
    expect(parseIds(`a, b\nc  d`)).toEqual(['a', 'b', 'c', 'd']);
  });
});

describe('deep links', () => {
  it('maps an item to its in-app page and refuses anything else', () => {
    expect(itemRoute('host', HOST)).toBe(`/inventory/hosts/${HOST}`);
    expect(itemRoute('container', HOST)).toBe(`/inventory/containers/${HOST}`);
    expect(itemRoute('check', CHECK)).toBe(`/checks/${CHECK}`);
    expect(itemRoute('host', '../../evil')).toBeNull();
    expect(itemRoute('host', 'javascript:alert(1)')).toBeNull();
  });
  it('routes the alert pages', () => {
    expect(resolveRoute('/alerts')).toEqual({ kind: 'section', path: '/alerts' });
    expect(resolveRoute('/alerts/rules')).toEqual({ kind: 'alerts', view: 'rules' });
    expect(resolveRoute(`/alerts/${A1}`)).toEqual({ kind: 'alert', id: A1 });
    expect(resolveRoute('/alerts/whatever').kind).toBe('not-found');
  });
});

describe('silence form (ALR-5)', () => {
  const now = new Date('2026-10-28T10:00:00Z');
  const at = (ms: number) => toLocalInput(new Date(now.getTime() + ms));
  const H = 3_600_000;
  const D = 24 * H;
  const ok = () => ({ ...emptySilenceForm(), ids: HOST, reason: 'Upgrade', endsAt: at(H) });

  it('accepts a valid silence', () => {
    expect(validateSilence(ok(), now)).toEqual({});
  });

  it('needs a selector, a reason of at most 200 characters and a future end', () => {
    expect(validateSilence({ ...ok(), ids: '' }, now).selector).toBeTruthy();
    expect(validateSilence({ ...ok(), reason: '' }, now).reason).toBeTruthy();
    expect(validateSilence({ ...ok(), reason: 'x'.repeat(201) }, now).reason).toBeTruthy();
    expect(validateSilence({ ...ok(), reason: 'x'.repeat(200) }, now)).toEqual({});
    expect(validateSilence({ ...ok(), endsAt: '' }, now).ends_at).toBeTruthy();
    expect(validateSilence({ ...ok(), endsAt: at(-H) }, now).ends_at).toBeTruthy();
  });

  it('limits a silence to 30 days and maintenance to 90', () => {
    expect(validateSilence({ ...ok(), endsAt: at(31 * D) }, now).ends_at).toContain('30 days');
    expect(validateSilence({ ...ok(), endsAt: at(29 * D) }, now)).toEqual({});
    const m = { ...ok(), kind: 'maintenance' as const };
    expect(validateSilence({ ...m, endsAt: at(80 * D) }, now)).toEqual({});
    expect(validateSilence({ ...m, endsAt: at(91 * D) }, now).ends_at).toContain('90 days');
  });

  it('limits a scheduled start to one year ahead and needs end after start', () => {
    const m = { ...ok(), kind: 'maintenance' as const };
    expect(
      validateSilence({ ...m, startsAt: at(366 * D), endsAt: at(367 * D) }, now).starts_at,
    ).toBeTruthy();
    expect(validateSilence({ ...m, startsAt: at(2 * D), endsAt: at(D) }, now).ends_at).toBeTruthy();
    expect(validateSilence({ ...m, startsAt: at(2 * D), endsAt: at(3 * D) }, now)).toEqual({});
  });

  it('builds the request body in UTC', () => {
    const input = silenceInput({ ...ok(), startsAt: at(D), endsAt: at(2 * D), tags: ['env:prod'] });
    expect(input.kind).toBe('silence');
    expect(input.selector).toEqual({ tags: ['env:prod'], ids: [HOST], severity: [], kinds: [] });
    expect(new Date(input.starts_at!).getTime()).toBe(now.getTime() + D);
    expect(input.ends_at).toMatch(/Z$/);
    expect(silenceInput(ok()).starts_at).toBeUndefined();
  });

  it('builds the 1h, 4h and 24h presets for one item', () => {
    for (const hours of [1, 4, 24]) {
      expect(itemSilence(HOST, hours, 'db-1', now)).toEqual({
        kind: 'silence',
        selector: { ids: [HOST] },
        ends_at: new Date(now.getTime() + hours * H).toISOString(),
        reason: 'Silenced from the alert page: db-1',
      });
    }
    expect(itemSilence(HOST, 1, 'x'.repeat(500), now).reason.length).toBe(200);
  });
});

describe('channel secrets are write-only', () => {
  it('keeps a stored secret when nothing is typed (key omitted)', () => {
    const f = formFromChannel(channel());
    expect(channelInput(f).config).toEqual({});
  });

  it('replaces a secret with the new value', () => {
    const f = formFromChannel(channel());
    f.url.input = 'https://hooks.example.com/new';
    expect(channelInput(f).config).toEqual({ url: 'https://hooks.example.com/new' });
  });

  it('clears a secret with an empty string', () => {
    const f = formFromChannel(
      channel({ type: 'telegram', config: { bot_token: { set: true }, chat_id: '1' } }),
    );
    f.telegram.botToken.clear = true;
    expect(channelInput(f).config).toEqual({ chat_id: '1', bot_token: '' });
  });

  it('never puts a stored value into the form', () => {
    const f = formFromChannel(channel());
    expect(JSON.stringify(f)).not.toContain('hooks.');
    expect(f.url).toEqual({ wasSet: true, input: '', clear: false });
  });

  it('handles webhook header secrets and SMTP passwords the same way', () => {
    const w = formFromChannel(
      channel({
        type: 'webhook',
        config: {
          url: { set: true },
          headers: [
            { name: 'X-Plain', value: 'v' },
            { name: 'X-Key', secret: true, secret_value: { set: true } },
          ],
        },
      }),
    );
    expect(channelInput(w).config).toEqual({
      headers: [
        { name: 'X-Plain', value: 'v' },
        { name: 'X-Key', secret: true },
      ],
    });
    w.headers[1]!.secretValue.input = 'rotated';
    expect((channelInput(w).config.headers as unknown[])[1]).toEqual({
      name: 'X-Key',
      secret: true,
      secret_value: 'rotated',
    });
    w.headers[1]!.secretValue.input = '';
    w.headers[1]!.secretValue.clear = true;
    expect((channelInput(w).config.headers as unknown[])[1]).toEqual({
      name: 'X-Key',
      secret: true,
      secret_value: '',
    });

    const s = formFromChannel(
      channel({
        type: 'smtp',
        config: {
          host: 'smtp.example.com',
          port: 587,
          security: 'starttls',
          username: 'u',
          password: { set: true },
          from: 'a@example.com',
          to: ['b@example.com'],
        },
      }),
    );
    expect(validateChannel(s)).toEqual({});
    expect(channelInput(s).config).toEqual({
      host: 'smtp.example.com',
      port: 587,
      security: 'starttls',
      username: 'u',
      from: 'a@example.com',
      to: ['b@example.com'],
    });
  });

  it('requires a secret on create and refuses unencrypted sign-in', () => {
    const f = { ...emptyChannelForm(), name: 'S' };
    expect(validateChannel(f)['config.url']).toBeTruthy();
    f.url.input = 'https://hooks.example.com/x';
    expect(validateChannel(f)).toEqual({});
    const s = { ...emptyChannelForm(), name: 'M', type: 'smtp' as const };
    s.smtp = {
      ...s.smtp,
      host: 'h',
      from: 'a@example.com',
      to: 'b@example.com',
      username: 'u',
      security: 'none',
    };
    expect(validateChannel(s)['config.security']).toBeTruthy();
  });
});

describe('routes list', () => {
  it('moves an item and stays put at the ends', () => {
    expect(move([1, 2, 3], 2, -1)).toEqual([1, 3, 2]);
    expect(move([1, 2, 3], 0, -1)).toEqual([1, 2, 3]);
    expect(move([1, 2, 3], 2, 1)).toEqual([1, 2, 3]);
    expect(move([1, 2, 3], 0, 1)).toEqual([2, 1, 3]);
  });
  it('builds the payload in order without client keys', () => {
    const list = [
      draftFrom(route({ continue: true })),
      draftFrom(route({ selector: { tags: ['env:prod'], severity: [], kinds: ['check_down'] } })),
    ];
    expect(routesPayload(move(list, 1, -1))).toEqual([
      {
        selector: { tags: ['env:prod'], severity: [], kinds: ['check_down'] },
        channel_id: CHAN,
        continue: false,
      },
      {
        selector: { tags: [], severity: ['critical'], kinds: [] },
        channel_id: CHAN,
        continue: true,
      },
    ]);
  });
});

describe('error hints', () => {
  it('has a hint for every ALR code in internal/errcode/codes.go, and no others', () => {
    const go = readFileSync(join(process.cwd(), '..', 'internal/errcode/codes.go'), 'utf8');
    const codes = [...go.matchAll(/Code = "(ALR-[A-Z]+-\d{3})"/g)].map((m) => m[1]);
    expect(codes.length).toBeGreaterThan(0);
    expect(Object.keys(ALERT_HINTS).sort()).toEqual([...codes].sort());
  });
});

describe('alerts page (ALR-5)', () => {
  const list = (items: AlertItem[]) => ({
    'GET /api/v1/alerts?state=active&limit=200': page(items),
  });

  it('lists alerts with severity text, an in-app item link, and who acknowledged', async () => {
    fakeServer(
      base(
        list([
          alertItem(A1),
          alertItem(A2, {
            state: 'acked',
            acked_by: 'Ada',
            severity: 'warning',
            item_type: 'check',
            item_id: CHECK,
            item_name: 'Website',
          }),
        ]),
      ),
    );
    await open('/alerts');
    const critical = await within(await screen.findByRole('table')).findByText('Critical');
    expect(critical).toBeTruthy();
    expect(within(screen.getByRole('table')).getByText('Warning')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'db-1' }).getAttribute('href')).toBe(
      `/inventory/hosts/${HOST}`,
    );
    expect(screen.getByRole('link', { name: 'Website' }).getAttribute('href')).toBe(
      `/checks/${CHECK}`,
    );
    expect(screen.getByText('Acknowledged by Ada')).toBeTruthy();
  });

  it('shows an empty state', async () => {
    fakeServer(base(list([])));
    await open('/alerts');
    expect(await screen.findByText('No active alerts')).toBeTruthy();
  });

  it('renders hostile names and summaries as text', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    fakeServer(
      base(
        list([
          alertItem(A1, { item_name: evil, summary: `<script>${evil}</script>`, rule_name: evil }),
        ]),
      ),
    );
    const { container } = await open('/alerts');
    await screen.findAllByText(evil);
    expect(container.querySelector('main img')).toBeNull();
    expect(container.querySelector('main script')).toBeNull();
  });

  it('refetches when the filters change', async () => {
    const calls = fakeServer(
      base({
        ...list([alertItem(A1)]),
        'GET /api/v1/alerts?state=resolved&severity=critical&limit=200': page([]),
        'GET /api/v1/alerts?state=resolved&limit=200': page([]),
      }),
    );
    await open('/alerts');
    await screen.findByText('Critical');
    await fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'resolved' } });
    await fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'critical' } });
    await waitFor(() =>
      expect(calls.some((c) => c.path.includes('state=resolved&severity=critical'))).toBe(true),
    );
    expect(await screen.findByText('No resolved alerts')).toBeTruthy();
  });

  it('acknowledges as an operator: CSRF header, disabled while busy, result shown', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const calls = fakeServer(
      base({
        ...as('operator'),
        ...list([alertItem(A1)]),
        [`POST /api/v1/alerts/${A1}/ack`]: async () => {
          await gate;
          return { status: 200, body: alertItem(A1, { state: 'acked', acked_by: 'Ada Admin' }) };
        },
      }),
    );
    await open('/alerts');
    const button = await screen.findByRole('button', { name: 'Acknowledge db-1 is offline' });
    await fireEvent.click(button);
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(true));
    release();
    expect(await screen.findByText('Acknowledged by Ada Admin')).toBeTruthy();
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.headers['X-CSRF-Token']).toBe('csrf-token-1');
    expect(screen.queryByRole('button', { name: /^Acknowledge/ })).toBeNull();
  });

  it('shows the server error when the alert resolved in the meantime', async () => {
    fakeServer(
      base({
        ...list([alertItem(A1)]),
        [`POST /api/v1/alerts/${A1}/ack`]: apiError(
          409,
          'ALR-RULE-001',
          'The alert is resolved.',
          'Reload the alert list.',
        ),
      }),
    );
    await open('/alerts');
    await fireEvent.click(await screen.findByRole('button', { name: /^Acknowledge/ }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('ALR-RULE-001');
  });

  it('hides write controls from viewers', async () => {
    fakeServer(base({ ...as('viewer'), ...list([alertItem(A1)]) }));
    await open('/alerts');
    await screen.findByText('Critical');
    expect(screen.queryByRole('button', { name: /^Acknowledge/ })).toBeNull();
  });

  it('stops its refresh timer when the page goes away', async () => {
    const clear = vi.spyOn(globalThis, 'clearInterval');
    fakeServer(base(list([])));
    await open('/alerts');
    await screen.findByText('No active alerts');
    clear.mockClear();
    cleanup();
    expect(clear).toHaveBeenCalled();
  });
});

describe('alert page and silence from an alert', () => {
  const routes = (extra: Record<string, Handler | Reply> = {}) =>
    base({
      ...as('operator'),
      [`GET /api/v1/alerts/${A1}`]: { status: 200, body: alertItem(A1) },
      ...extra,
    });

  it('has a prominent link to the item and facts', async () => {
    fakeServer(routes());
    await open(`/alerts/${A1}`);
    const link = await screen.findByRole('link', { name: /Open host: db-1/ });
    expect(link.getAttribute('href')).toBe(`/inventory/hosts/${HOST}`);
    expect(screen.getByText('Hosts offline (Host is offline)')).toBeTruthy();
  });

  it.each([
    ['1 hour', 1],
    ['4 hours', 4],
    ['24 hours', 24],
  ])('silences the item for %s with an ids selector', async (label, hours) => {
    const calls = fakeServer(routes({ 'POST /api/v1/silences': { status: 201, body: silence() } }));
    await open(`/alerts/${A1}`);
    await fireEvent.click(await screen.findByRole('button', { name: label }));
    await screen.findByText(/are silenced for/);
    const body = calls.find((c) => c.method === 'POST')!.body as {
      selector: { ids: string[] };
      ends_at: string;
      kind: string;
    };
    expect(body.kind).toBe('silence');
    expect(body.selector).toEqual({ ids: [HOST] });
    const diff = new Date(body.ends_at).getTime() - Date.now();
    expect(Math.abs(diff - hours * 3_600_000)).toBeLessThan(60_000);
  });

  it('offers no silence to viewers', async () => {
    fakeServer(
      base({ ...as('viewer'), [`GET /api/v1/alerts/${A1}`]: { status: 200, body: alertItem(A1) } }),
    );
    await open(`/alerts/${A1}`);
    await screen.findByRole('link', { name: /Open host/ });
    expect(screen.queryByRole('button', { name: '1 hour' })).toBeNull();
  });

  it('explains a missing alert', async () => {
    fakeServer(
      base({
        [`GET /api/v1/alerts/${A1}`]: apiError(
          404,
          'API-NF-001',
          'Not found.',
          'Check the address.',
        ),
      }),
    );
    await open(`/alerts/${A1}`);
    expect(await screen.findByText('Alert not found')).toBeTruthy();
  });
});

describe('silences view', () => {
  it('lists silences and ends one after confirming', async () => {
    const calls = fakeServer(
      base({
        ...as('operator'),
        'GET /api/v1/silences?limit=200&active=true': page([silence()]),
        [`DELETE /api/v1/silences/${SIL}`]: { status: 204 },
      }),
    );
    await open('/alerts/silences');
    await screen.findByText('Upgrading db-1');
    await fireEvent.click(screen.getByRole('button', { name: 'End Upgrading db-1' }));
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await fireEvent.click(screen.getByRole('button', { name: /^Yes, end it/ }));
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE')).toBe(true));
    expect(await screen.findByText('No silences')).toBeTruthy();
  });

  it('validates the form, then posts a maintenance window', async () => {
    const calls = fakeServer(
      base({
        ...as('operator'),
        'GET /api/v1/silences?limit=200&active=true': page([]),
        'POST /api/v1/silences': { status: 201, body: silence({ kind: 'maintenance' }) },
      }),
    );
    await open('/alerts/silences');
    await fireEvent.click(await screen.findByRole('button', { name: 'New silence' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(byId('sil-reason').getAttribute('aria-invalid')).toBe('true');
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await fireEvent.change(byId('sil-kind'), { target: { value: 'maintenance' } });
    await fireEvent.input(byId('sil-selector-tags'), { target: { value: 'env:staging' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add Tags' }));
    await fireEvent.input(byId('sil-reason'), { target: { value: 'Planned work' } });
    await fireEvent.input(byId('sil-ends-at'), {
      target: { value: toLocalInput(new Date(Date.now() + 2 * 86_400_000)) },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const body = calls.find((c) => c.method === 'POST')!.body as Record<string, unknown>;
    expect(body).toMatchObject({
      kind: 'maintenance',
      reason: 'Planned work',
      selector: { tags: ['env:staging'], ids: [], severity: [], kinds: [] },
    });
  });

  it('gives viewers the list without write controls', async () => {
    fakeServer(
      base({ ...as('viewer'), 'GET /api/v1/silences?limit=200&active=true': page([silence()]) }),
    );
    await open('/alerts/silences');
    await screen.findByText('Upgrading db-1');
    expect(screen.queryByRole('button', { name: 'New silence' })).toBeNull();
    expect(screen.queryByRole('button', { name: /^End / })).toBeNull();
  });
});

describe('rules view', () => {
  const ruleRoutes = (extra: Record<string, Handler | Reply> = {}) =>
    base({
      ...as('operator'),
      'GET /api/v1/rules?limit=500': page([rule()]),
      [`GET /api/v1/rules/${RULE}`]: { status: 200, body: rule(), headers: { ETag: '"v3"' } },
      ...extra,
    });

  it('toggles a rule with If-Match from a fresh read', async () => {
    const calls = fakeServer(
      ruleRoutes({
        [`PUT /api/v1/rules/${RULE}`]: {
          status: 200,
          body: rule({ enabled: false }),
          headers: { ETag: '"v4"' },
        },
      }),
    );
    await open('/alerts/rules');
    await fireEvent.click(await screen.findByLabelText('Enabled: Hosts offline'));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['If-Match']).toBe('"v3"');
    expect(put.body).toMatchObject({ enabled: false, kind: 'host_offline', params: { for_s: 60 } });
  });

  it('edits a rule with the kind fixed, and sends If-Match', async () => {
    const calls = fakeServer(
      ruleRoutes({
        [`PUT /api/v1/rules/${RULE}`]: { status: 200, body: rule(), headers: { ETag: '"v4"' } },
      }),
    );
    await open('/alerts/rules');
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit Hosts offline' }));
    await screen.findByRole('heading', { name: 'Edit rule' });
    expect(byId('rule-kind')).toHaveProperty('disabled', true);
    await fireEvent.input(byId('rule-name'), { target: { value: 'Renamed' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['If-Match']).toBe('"v3"');
    expect(put.body).toMatchObject({
      name: 'Renamed',
      selector: { tags: ['env:production'], ids: [] },
    });
  });

  it('reloads after a 412 and shows the server message for a 428', async () => {
    let reads = 0;
    fakeServer(
      ruleRoutes({
        [`GET /api/v1/rules/${RULE}`]: () => {
          reads++;
          return {
            status: 200,
            body: rule({ name: reads === 1 ? 'Hosts offline' : 'Changed elsewhere' }),
            headers: { ETag: `"v${reads}"` },
          };
        },
        [`PUT /api/v1/rules/${RULE}`]: apiError(412, 'API-PRE-001', 'The rule changed.', 'Reload.'),
      }),
    );
    await open('/alerts/rules');
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit Hosts offline' }));
    await screen.findByRole('heading', { name: 'Edit rule' });
    await waitFor(() => expect(byId('rule-name').value).toBe('Hosts offline'));
    await fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    await waitFor(() => expect(byId('rule-name').value).toBe('Changed elsewhere'));
    expect(screen.getByText(/changed while you were editing/)).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('API-PRE-001');
  });

  it('shows the missing If-Match error (428)', async () => {
    fakeServer(
      ruleRoutes({
        [`PUT /api/v1/rules/${RULE}`]: apiError(
          428,
          'API-PRE-002',
          'If-Match is required.',
          'Reload the rule.',
        ),
      }),
    );
    await open('/alerts/rules');
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit Hosts offline' }));
    await waitFor(() => expect(byId('rule-name')?.value).toBe('Hosts offline'));
    await fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    expect((await screen.findByRole('alert')).textContent).toContain('API-PRE-002');
  });

  it('creates a rule with per-kind fields and puts a 422 on its field', async () => {
    const calls = fakeServer(
      ruleRoutes({
        'POST /api/v1/rules': apiError(
          422,
          'API-VAL-001',
          'Disk is host only.',
          'Use a host.',
          'params.metric',
        ),
      }),
    );
    await open('/alerts/rules');
    await fireEvent.click(await screen.findByRole('button', { name: 'Add rule' }));
    await fireEvent.input(await screen.findByLabelText(/^Name/), { target: { value: 'Busy' } });
    await fireEvent.change(byId('rule-kind'), { target: { value: 'metric_threshold' } });
    await fireEvent.input(byId('rule-params-threshold'), { target: { value: '150' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    expect(byId('rule-params-threshold').getAttribute('aria-invalid')).toBe('true');
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    await fireEvent.input(byId('rule-params-threshold'), { target: { value: '90' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    await waitFor(() =>
      expect(byId('rule-params-metric').getAttribute('aria-invalid')).toBe('true'),
    );
    expect(calls.find((c) => c.method === 'POST')!.body).toMatchObject({
      kind: 'metric_threshold',
      params: { target: 'host', metric: 'cpu', threshold: 90 },
    });
  });

  it('adds tag chips with validation', async () => {
    fakeServer(ruleRoutes());
    await open('/alerts/rules');
    await fireEvent.click(await screen.findByRole('button', { name: 'Add rule' }));
    await screen.findByRole('heading', { name: 'Add rule' });
    await fireEvent.input(byId('rule-selector-tags'), { target: { value: 'bad tag' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add Tags' }));
    expect(byId('rule-selector-tags').getAttribute('aria-invalid')).toBe('true');
    await fireEvent.input(byId('rule-selector-tags'), { target: { value: 'env:production' } });
    await fireEvent.keyDown(byId('rule-selector-tags'), { key: 'Enter' });
    expect(screen.getByRole('button', { name: 'Remove env:production' })).toBeTruthy();
  });

  it('is read-only for viewers', async () => {
    fakeServer(base({ ...as('viewer'), 'GET /api/v1/rules?limit=500': page([rule()]) }));
    await open('/alerts/rules');
    await screen.findByText('Hosts offline');
    expect(screen.queryByRole('button', { name: 'Add rule' })).toBeNull();
    expect(screen.queryByLabelText('Enabled: Hosts offline')).toBeNull();
  });
});

describe('channels view (admin only)', () => {
  const chanRoutes = (extra: Record<string, Handler | Reply> = {}) =>
    base({
      'GET /api/v1/channels?limit=500': page([channel()]),
      [`GET /api/v1/channels/${CHAN}`]: { status: 200, body: channel(), headers: { ETag: '"c1"' } },
      ...extra,
    });

  it.each([['viewer'], ['operator']])('does not call the API for a %s', async (role) => {
    const calls = fakeServer(base(as(role)));
    await open('/alerts/channels');
    expect(await screen.findByText('Administrator access needed')).toBeTruthy();
    expect(calls.some((c) => c.path.includes('/channels'))).toBe(false);
    cleanup();
    router.navigate('/alerts/routes');
    render(App);
    expect(await screen.findByText('Administrator access needed')).toBeTruthy();
    expect(calls.some((c) => c.path.includes('/routes') || c.path.includes('/channels'))).toBe(
      false,
    );
  });

  it('lists channels with their last status and never shows a secret', async () => {
    fakeServer(
      chanRoutes({
        'GET /api/v1/channels?limit=500': page([
          channel({ last_status: 'failed', last_error_code: 'ALR-SEND-002', last_sent_at: NOW }),
        ]),
      }),
    );
    const { container } = await open('/alerts/channels');
    await screen.findByText('On-call Slack');
    expect(container.textContent).toContain('Last send failed (ALR-SEND-002)');
  });

  it('handles test send: success, 429 and 502 with the ALR code and hint', async () => {
    let n = 0;
    fakeServer(
      chanRoutes({
        [`POST /api/v1/channels/${CHAN}/test`]: () => {
          n++;
          if (n === 1) return { status: 200, body: { ok: true } };
          if (n === 2) return apiError(429, 'ALR-SEND-006', 'Too often.', 'Wait.');
          return apiError(502, 'ALR-SEND-003', 'Blocked.', 'x');
        },
      }),
    );
    await open('/alerts/channels');
    const send = async () =>
      fireEvent.click(await screen.findByRole('button', { name: 'Send test to On-call Slack' }));
    await send();
    expect(await screen.findByText('Test message sent to On-call Slack.')).toBeTruthy();
    await send();
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('ALR-SEND-006'));
    expect(screen.getByRole('alert').textContent).toContain('Wait a few seconds');
    await send();
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('ALR-SEND-003'));
    expect(screen.getByRole('alert').textContent).toContain('Allow private addresses');
  });

  it('keeps a stored secret on save and sends If-Match', async () => {
    const calls = fakeServer(
      chanRoutes({
        [`PUT /api/v1/channels/${CHAN}`]: {
          status: 200,
          body: channel(),
          headers: { ETag: '"c2"' },
        },
      }),
    );
    await open('/alerts/channels');
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit On-call Slack' }));
    await waitFor(() => expect(byId('chan-name')?.value).toBe('On-call Slack'));
    expect(screen.getByText('A value is set. It is write-only and cannot be shown.')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Save channel' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['If-Match']).toBe('"c1"');
    expect(put.body).toEqual({
      name: 'On-call Slack',
      type: 'slack',
      enabled: true,
      allow_private: false,
      config: {},
    });
  });

  it('replaces and clears the secret from the editor, and warns about private addresses', async () => {
    const calls = fakeServer(
      chanRoutes({
        [`PUT /api/v1/channels/${CHAN}`]: {
          status: 200,
          body: channel(),
          headers: { ETag: '"c2"' },
        },
      }),
    );
    await open('/alerts/channels');
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit On-call Slack' }));
    await waitFor(() => expect(byId('chan-name')?.value).toBe('On-call Slack'));
    await fireEvent.click(screen.getByLabelText('Allow private addresses'));
    expect(screen.getByRole('note').textContent).toMatch(/private\s+network/);
    await fireEvent.input(screen.getByLabelText('Slack webhook URL'), {
      target: { value: 'https://hooks.example.com/new' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Save channel' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect(calls.find((c) => c.method === 'PUT')!.body).toMatchObject({
      allow_private: true,
      config: { url: 'https://hooks.example.com/new' },
    });
  });

  it('refuses a 412 by reloading, and shows 428', async () => {
    fakeServer(
      chanRoutes({
        [`PUT /api/v1/channels/${CHAN}`]: apiError(
          428,
          'API-PRE-002',
          'If-Match is required.',
          'Reload.',
        ),
      }),
    );
    await open('/alerts/channels');
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit On-call Slack' }));
    await waitFor(() => expect(byId('chan-name')?.value).toBe('On-call Slack'));
    await fireEvent.click(screen.getByRole('button', { name: 'Save channel' }));
    expect((await screen.findByRole('alert')).textContent).toContain('API-PRE-002');
  });

  it('creates a webhook channel with a secret header', async () => {
    const calls = fakeServer(
      chanRoutes({ 'POST /api/v1/channels': { status: 201, body: channel({ type: 'webhook' }) } }),
    );
    await open('/alerts/channels');
    await fireEvent.click(await screen.findByRole('button', { name: 'Add channel' }));
    await fireEvent.change(await screen.findByLabelText('Type'), { target: { value: 'webhook' } });
    await fireEvent.input(byId('chan-name'), { target: { value: 'Hook' } });
    await fireEvent.input(screen.getByLabelText('Webhook URL'), {
      target: { value: 'https://example.com/hook' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Add a header' }));
    await fireEvent.input(screen.getByLabelText('Header 1 name'), { target: { value: 'X-Key' } });
    await fireEvent.click(screen.getByLabelText('Secret'));
    await fireEvent.input(screen.getByLabelText('Header 1 secret value'), {
      target: { value: 's3cret' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Save channel' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
      name: 'Hook',
      type: 'webhook',
      enabled: true,
      allow_private: false,
      config: {
        url: 'https://example.com/hook',
        headers: [{ name: 'X-Key', secret: true, secret_value: 's3cret' }],
      },
    });
  });
});

describe('routes view (admin only)', () => {
  const routeRoutes = (extra: Record<string, Handler | Reply> = {}) =>
    base({
      'GET /api/v1/routes': {
        status: 200,
        body: {
          routes: [
            route({ id: 'r1' }),
            route({
              id: 'r2',
              selector: { tags: ['env:prod'], severity: [], kinds: [] },
              continue: true,
            }),
          ],
        },
        headers: { ETag: '"r5"' },
      },
      'GET /api/v1/channels?limit=500': page([channel()]),
      ...extra,
    });

  it('explains that no matching route means not sent', async () => {
    fakeServer(routeRoutes());
    await open('/alerts/routes');
    expect(
      await screen.findByText(
        /If no route matches, the alert is recorded but no notification is sent/,
      ),
    ).toBeTruthy();
  });

  it('reorders with the keyboard-reachable buttons and saves with If-Match', async () => {
    const calls = fakeServer(
      routeRoutes({
        'PUT /api/v1/routes': (c: Call) => ({
          status: 200,
          body: c.body,
          headers: { ETag: '"r6"' },
        }),
      }),
    );
    await open('/alerts/routes');
    const up = await screen.findByRole('button', { name: 'Move route 2 up' });
    expect(
      (screen.getByRole('button', { name: 'Move route 1 up' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    await fireEvent.click(up);
    await screen.findByText('Route moved to position 1 of 2');
    await fireEvent.click(screen.getByRole('button', { name: 'Save routes' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['If-Match']).toBe('"r5"');
    const sent = (put.body as { routes: RouteEntry[] }).routes;
    expect(sent.map((r) => r.continue)).toEqual([true, false]);
    expect(sent[0]!.selector.tags).toEqual(['env:prod']);
    expect(sent[0]).not.toHaveProperty('id');
  });

  it('adds a catch-all route and rejects a missing channel', async () => {
    const calls = fakeServer(
      routeRoutes({
        'PUT /api/v1/routes': { status: 200, body: { routes: [] }, headers: { ETag: '"r6"' } },
      }),
    );
    await open('/alerts/routes');
    await fireEvent.click(await screen.findByRole('button', { name: 'Add route' }));
    const selects = screen.getAllByLabelText(/^Send to \(route 3\)/);
    await fireEvent.change(selects[0]!, { target: { value: '' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save routes' }));
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    expect(screen.getByText('Choose a channel.')).toBeTruthy();
  });

  it('reloads on 412 and shows 428', async () => {
    let n = 0;
    fakeServer(
      routeRoutes({
        'PUT /api/v1/routes': () =>
          ++n === 1
            ? apiError(412, 'API-PRE-001', 'Changed.', 'Reload.')
            : apiError(428, 'API-PRE-002', 'If-Match is required.', 'Reload.'),
      }),
    );
    await open('/alerts/routes');
    await fireEvent.click(await screen.findByRole('button', { name: 'Save routes' }));
    await screen.findByText(/routes changed while you were editing/);
    await fireEvent.click(screen.getByRole('button', { name: 'Save routes' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('API-PRE-002'));
  });
});

describe('accessibility (axe)', () => {
  it('has no violations on the alerts page', async () => {
    fakeServer(
      base({
        ...as('operator'),
        'GET /api/v1/alerts?state=active&limit=200': page([
          alertItem(A1),
          alertItem(A2, { state: 'acked', acked_by: 'Ada' }),
        ]),
      }),
    );
    const { container } = await open('/alerts');
    await screen.findByText('Critical');
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on an alert page', async () => {
    fakeServer(
      base({
        ...as('operator'),
        [`GET /api/v1/alerts/${A1}`]: { status: 200, body: alertItem(A1) },
      }),
    );
    const { container } = await open(`/alerts/${A1}`);
    await screen.findByRole('link', { name: /Open host/ });
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on rules, with the editor open and with errors', async () => {
    fakeServer(base({ ...as('operator'), 'GET /api/v1/rules?limit=500': page([rule()]) }));
    const { container } = await open('/alerts/rules');
    await screen.findByText('Hosts offline');
    expect(await violations(container)).toEqual([]);
    await fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    await screen.findByRole('heading', { name: 'Add rule' });
    await fireEvent.change(byId('rule-kind'), { target: { value: 'container_stopped' } });
    expect(await violations(container)).toEqual([]);
    await fireEvent.input(byId('rule-name'), { target: { value: '' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    expect(byId('rule-name').getAttribute('aria-invalid')).toBe('true');
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on silences, list and form', async () => {
    fakeServer(
      base({ ...as('operator'), 'GET /api/v1/silences?limit=200&active=true': page([silence()]) }),
    );
    const { container } = await open('/alerts/silences');
    await screen.findByText('Upgrading db-1');
    expect(await violations(container)).toEqual([]);
    await fireEvent.click(screen.getByRole('button', { name: 'New silence' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Create' }));
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on channels, list and editors', async () => {
    fakeServer(
      base({
        'GET /api/v1/channels?limit=500': page([
          channel({ last_status: 'failed', last_error_code: 'ALR-SEND-002' }),
        ]),
      }),
    );
    const { container } = await open('/alerts/channels');
    await screen.findByText('On-call Slack');
    expect(await violations(container)).toEqual([]);
    await fireEvent.click(screen.getByRole('button', { name: 'Add channel' }));
    for (const type of ['smtp', 'telegram', 'webhook']) {
      await fireEvent.change(await screen.findByLabelText('Type'), { target: { value: type } });
      if (type === 'webhook')
        await fireEvent.click(screen.getByRole('button', { name: 'Add a header' }));
      expect(await violations(container)).toEqual([]);
    }
    await fireEvent.click(screen.getByRole('button', { name: 'Save channel' }));
    expect(await violations(container)).toEqual([]);
  });

  it('has no violations on routes and on the admin-needed notice', async () => {
    fakeServer(
      base({
        'GET /api/v1/routes': {
          status: 200,
          body: { routes: [route()] },
          headers: { ETag: '"r1"' },
        },
        'GET /api/v1/channels?limit=500': page([channel()]),
      }),
    );
    const { container } = await open('/alerts/routes');
    await screen.findByRole('button', { name: 'Save routes' });
    expect(await violations(container)).toEqual([]);
    cleanup();
    fakeServer(base(as('viewer')));
    const second = await open('/alerts/routes');
    await screen.findByText('Administrator access needed');
    expect(await violations(second.container)).toEqual([]);
  });
});
