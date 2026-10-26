// SPDX-License-Identifier: AGPL-3.0-only

import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import axe from 'axe-core';
import { flushSync } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LogStream, MAX_RETRIES } from './lib/logstream.svelte';
import {
  BUFFER_LINES,
  compileFilter,
  detectLevel,
  LogBuffer,
  MAX_PATTERN_CHARS,
  MAX_REGEX_LINE_CHARS,
  parseFrame,
  UNIT_PATTERN,
} from './lib/logs';
import JournalLogs from './lib/ui/JournalLogs.svelte';
import LogViewer from './lib/ui/LogViewer.svelte';
import { apiError, fakeServer } from './test-helpers';

class MockSocket {
  static all: MockSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(readonly url: string) {
    MockSocket.all.push(this);
  }
  close(): void {
    this.closed = true;
  }
  open(): void {
    this.onopen?.();
  }
  send(o: unknown): void {
    this.onmessage?.({ data: typeof o === 'string' ? o : JSON.stringify(o) });
  }
  drop(): void {
    this.onclose?.();
  }
}
const last = (): MockSocket => MockSocket.all[MockSocket.all.length - 1]!;
const line = (text: string, stream = 'stdout') => ({
  type: 'line',
  ts: 1_700_000_000_000,
  stream,
  text,
});

beforeEach(() => {
  MockSocket.all = [];
  vi.stubGlobal('WebSocket', MockSocket);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('LOG-1 frame validation', () => {
  it('accepts well-formed frames', () => {
    expect(parseFrame(JSON.stringify(line('hi', 'stderr')))).toMatchObject({
      type: 'line',
      stream: 'stderr',
      text: 'hi',
    });
    expect(
      parseFrame('{"type":"notice","code":"LOG-STR-003","message":"m","dropped":3}'),
    ).toMatchObject({ dropped: 3, code: 'LOG-STR-003' });
    expect(
      parseFrame('{"type":"end","reason":"agent_offline","code":"LOG-SRC-003"}'),
    ).toMatchObject({ reason: 'agent_offline' });
  });
  it('rejects malformed, unknown and oversize frames', () => {
    for (const bad of [
      'nope',
      '[]',
      '{"type":"mystery"}',
      '{"type":"line","ts":"x","text":"a"}',
      '{"type":"line","ts":1}',
      '{"type":"end","reason":"because"}',
      '{"type":"notice"}',
      new ArrayBuffer(4),
      'x'.repeat(300_000),
    ])
      expect(parseFrame(bad)).toBeNull();
  });
  it('drops hostile codes and unknown streams safely', () => {
    const f = parseFrame('{"type":"end","reason":"source_error","code":"<img>"}');
    expect(f).toMatchObject({ code: '' });
    expect(parseFrame('{"type":"line","ts":1,"stream":"x","text":"a"}')).toMatchObject({
      stream: 'stdout',
    });
  });
});

describe('level detection', () => {
  it('reads JSON, logfmt and keywords', () => {
    expect(detectLevel('{"level":"error","msg":"x"}')).toBe('error');
    expect(detectLevel('{"severity":"WARNING"}')).toBe('warn');
    expect(detectLevel('{"lvl":"debug"}')).toBe('debug');
    expect(detectLevel('time=1 level=info msg=hi')).toBe('info');
    expect(detectLevel('level="warn" x=1')).toBe('warn');
    expect(detectLevel('2024 ERROR boom')).toBe('error');
    expect(detectLevel('WARN: disk')).toBe('warn');
    expect(detectLevel('plain text')).toBe('none');
    expect(detectLevel('{broken json')).toBe('none');
  });
});

describe('filters', () => {
  const l = (text: string) => ({
    id: 1,
    ts: 0,
    stream: 'stdout' as const,
    text,
    level: 'none' as const,
  });
  it('matches text case-insensitively', () => {
    expect(compileFilter('ERR', 'text').test?.(l('an error'))).toBe(true);
    expect(compileFilter('zzz', 'text').test?.(l('an error'))).toBe(false);
  });
  it('matches regex and reports invalid patterns inline', () => {
    expect(compileFilter('^an\\s+err', 'regex').test?.(l('an error'))).toBe(true);
    const bad = compileFilter('(', 'regex');
    expect(bad.error).toMatch(/not valid/);
    expect(bad.test).toBeNull();
  });
  it('refuses over-long and nested-repeat patterns, and skips long lines', () => {
    expect(compileFilter('a'.repeat(MAX_PATTERN_CHARS + 1), 'regex').error).toMatch(/too long/);
    expect(compileFilter('(a+)+$', 'regex').error).toMatch(/too complex/);
    const f = compileFilter('x', 'regex');
    expect(f.test?.(l('x'.repeat(MAX_REGEX_LINE_CHARS + 1)))).toBe(false);
  });
  it('validates journal unit names', () => {
    expect(UNIT_PATTERN.test('sshd.service')).toBe(true);
    expect(UNIT_PATTERN.test('user@1000.service')).toBe(true);
    expect(UNIT_PATTERN.test('-x')).toBe(false);
    expect(UNIT_PATTERN.test('a b')).toBe(false);
    expect(UNIT_PATTERN.test('a/b')).toBe(false);
  });
});

describe('LOG-1 buffer', () => {
  it('drops the oldest lines beyond capacity', () => {
    const b = new LogBuffer(5);
    b.push(Array.from({ length: 8 }, (_, i) => b.make(i, 'stdout', `l${i}`)));
    expect(b.lines.map((x) => x.text)).toEqual(['l3', 'l4', 'l5', 'l6', 'l7']);
    expect(b.dropped).toBe(3);
  });
});

describe('LogStream', () => {
  it('connects same-origin without a server filter, goes live and buffers lines', () => {
    const s = new LogStream();
    s.connect('container:C1');
    expect(last().url).toMatch(
      /^ws:\/\/[^/]+\/api\/v1\/logs\/stream\?target=container%3AC1&tail=100$/,
    );
    expect(s.state).toBe('connecting');
    last().open();
    expect(s.state).toBe('live');
    last().send(line('one'));
    last().send('garbage');
    last().send({ type: 'weird' });
    s.flush();
    expect(s.buffer.lines.map((x) => x.text)).toEqual(['one']);
  });

  it('pauses, counts unseen lines and resumes', () => {
    const s = new LogStream();
    s.connect('container:C1');
    last().open();
    s.pause();
    for (let i = 0; i < 3; i++) last().send(line(`p${i}`));
    s.flush();
    expect(s.unseen).toBe(3);
    expect(s.buffer.lines).toHaveLength(0);
    s.resume();
    expect(s.unseen).toBe(0);
    expect(s.buffer.lines).toHaveLength(3);
  });

  it('bounds the held lines while paused', () => {
    const s = new LogStream();
    s.connect('container:C1');
    last().open();
    s.pause();
    for (let i = 0; i < BUFFER_LINES + 100; i++) last().send(line(`p${i}`));
    s.flush();
    expect(s.unseen).toBe(BUFFER_LINES);
  });

  it('stays bounded under a 20k line burst', () => {
    const s = new LogStream();
    s.connect('container:C1');
    last().open();
    const t0 = performance.now();
    for (let burst = 0; burst < 20; burst++) {
      for (let i = 0; i < 1000; i++) last().send(line(`{"level":"info","n":${burst * 1000 + i}}`));
      s.flush();
    }
    expect(s.buffer.lines).toHaveLength(BUFFER_LINES);
    expect(s.buffer.lines.at(-1)?.text).toContain('19999');
    expect(performance.now() - t0).toBeLessThan(5000);
  });

  it('shows notices and the end reason with its code', () => {
    const s = new LogStream();
    s.connect('container:C1');
    last().open();
    last().send({ type: 'notice', code: 'LOG-STR-003', message: 'slow', dropped: 4 });
    last().send({ type: 'end', reason: 'agent_offline', code: 'LOG-SRC-003' });
    expect(s.state).toBe('ended');
    expect(s.statusText).toContain('LOG-SRC-003');
    expect(s.buffer.lines[0]?.stream).toBe('notice');
    last().drop();
    expect(MockSocket.all).toHaveLength(1); // an ended stream never reconnects by itself
  });

  it('retries a network drop a limited number of times with tail=0, then stops', async () => {
    vi.useFakeTimers();
    fakeServer({
      [`GET /api/v1/logs/stream?target=container%3AC1&tail=0`]: {
        status: 400,
        body: { error: { code: 'API-VAL-001', message: 'm', hint: 'h' } },
      },
    });
    const s = new LogStream();
    s.connect('container:C1');
    last().open();
    for (let i = 0; i < MAX_RETRIES; i++) {
      last().drop();
      await vi.advanceTimersByTimeAsync(5_000);
      expect(last().url).toContain('tail=0');
    }
    expect(MockSocket.all).toHaveLength(1 + MAX_RETRIES);
    last().drop();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(MockSocket.all).toHaveLength(1 + MAX_RETRIES);
    expect(s.state).toBe('error');
    s.reconnect();
    expect(MockSocket.all).toHaveLength(2 + MAX_RETRIES);
    expect(s.retry).toBe(0);
  });

  it('reads the refusal over HTTP when the handshake fails and does not retry', async () => {
    fakeServer({
      'GET /api/v1/logs/stream?target=container%3AC1&tail=100': apiError(
        409,
        'LOG-SRC-003',
        'The host is offline.',
        'Wait for it.',
      ),
    });
    const s = new LogStream();
    s.connect('container:C1');
    last().drop();
    await vi.waitFor(() => expect(s.state).toBe('error'));
    expect(s.errorCode).toBe('LOG-SRC-003');
    expect(s.errorHint).toBe('Wait for it.');
    expect(MockSocket.all).toHaveLength(1);
  });

  it('closes the socket on close()', () => {
    const s = new LogStream();
    s.connect('container:C1');
    const sock = last();
    s.close();
    expect(sock.closed).toBe(true);
  });
});

describe('LogViewer', () => {
  async function live() {
    const view = render(LogViewer, { props: { target: 'container:C1' } });
    const sock = last();
    sock.open();
    return { ...view, sock };
  }

  it('renders hostile text inertly', async () => {
    const { sock, container } = await live();
    sock.send(line('<img src=x onerror=alert(1)><script>alert(2)</script>'));
    await vi.waitFor(() => expect(container.querySelector('.msg')).not.toBeNull());
    expect(container.querySelector('.msg img, .msg script')).toBeNull();
    expect(container.querySelector('.msg')?.textContent).toBe(
      '<img src=x onerror=alert(1)><script>alert(2)</script>',
    );
  });

  it('marks stderr, filters, and reports an invalid regex without throwing', async () => {
    const { sock, container } = await live();
    sock.send(line('alpha'));
    sock.send(line('beta', 'stderr'));
    await vi.waitFor(() => expect(container.querySelectorAll('.row')).toHaveLength(2));
    expect(container.querySelector('.stream-stderr .tag')?.textContent).toBe('stderr');
    await fireEvent.input(screen.getByLabelText('Filter'), { target: { value: 'alp' } });
    await vi.waitFor(() => expect(container.querySelectorAll('.row')).toHaveLength(1));
    await fireEvent.change(screen.getByLabelText('Match as'), { target: { value: 'regex' } });
    await fireEvent.input(screen.getByLabelText('Filter'), { target: { value: '(' } });
    expect(await screen.findByText(/not valid/)).toBeTruthy();
  });

  it('shows a log region that does not announce, and a polite status', async () => {
    const { container } = await live();
    const region = container.querySelector('[role="log"]');
    expect(region?.getAttribute('aria-live')).toBe('off');
    expect(container.querySelector('[role="status"]')?.getAttribute('aria-live')).toBe('polite');
  });

  it('pauses, counts and resumes via the buttons; clears', async () => {
    const { sock, container } = await live();
    await fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
    sock.send(line('held'));
    await screen.findByRole('button', { name: 'Resume (1 new)' });
    expect(container.querySelectorAll('.row')).toHaveLength(0);
    await fireEvent.click(screen.getByRole('button', { name: /Resume/ }));
    await vi.waitFor(() => expect(container.querySelectorAll('.row')).toHaveLength(1));
    await fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    await vi.waitFor(() => expect(container.querySelectorAll('.row')).toHaveLength(0));
  });

  it('offers jump-to-latest after scrolling up and follows again on jump', async () => {
    const { container } = await live();
    const region = container.querySelector('[role="log"]') as HTMLElement;
    Object.defineProperty(region, 'scrollHeight', { value: 1000, configurable: true });
    Object.defineProperty(region, 'clientHeight', { value: 100, configurable: true });
    region.scrollTop = 0;
    await fireEvent.scroll(region);
    const jump = await screen.findByRole('button', { name: 'Jump to latest' });
    await fireEvent.click(jump);
    await vi.waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Jump to latest' })).toBeNull(),
    );
  });

  it('windows rendering for a full buffer', async () => {
    const { sock, container } = await live();
    for (let i = 0; i < 3000; i++) sock.send(line(`row ${i}`));
    await vi.waitFor(() => expect(container.querySelectorAll('.row').length).toBeGreaterThan(0));
    expect(container.querySelectorAll('.row').length).toBeLessThan(200);
  });

  it('shows the error code and hint and a Reconnect button', async () => {
    fakeServer({
      'GET /api/v1/logs/stream?target=container%3AC1&tail=100': apiError(
        429,
        'LOG-STR-001',
        'Too many.',
        'Wait.',
      ),
    });
    render(LogViewer, { props: { target: 'container:C1' } });
    last().drop();
    expect(await screen.findByRole('button', { name: 'Reconnect' })).toBeTruthy();
    expect(screen.getAllByText(/LOG-STR-001/).length).toBeGreaterThan(0);
  });

  it('closes the socket on unmount', async () => {
    const { sock, unmount } = await live();
    unmount();
    expect(sock.closed).toBe(true);
  });

  it('has no axe violations', async () => {
    const { sock, container } = await live();
    sock.send(line('ERROR boom', 'stderr'));
    flushSync();
    const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

describe('JournalLogs', () => {
  it('rejects bad unit names and opens a journal target for valid ones', async () => {
    const { container } = render(JournalLogs, { props: { hostId: 'H1' } });
    const input = screen.getByLabelText('Journal unit');
    await fireEvent.input(input, { target: { value: '../etc' } });
    expect(screen.getByRole('button', { name: 'View logs' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByText(/letters, digits/)).toBeTruthy();
    await fireEvent.input(input, { target: { value: 'sshd.service' } });
    await fireEvent.click(screen.getByRole('button', { name: 'View logs' }));
    await vi.waitFor(() => expect(MockSocket.all).toHaveLength(1));
    expect(decodeURIComponent(last().url)).toContain('target=journal:H1:sshd.service');
    const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});
