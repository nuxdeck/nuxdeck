// SPDX-License-Identifier: AGPL-3.0-only

// Pure log-viewer logic: frame validation, level detection, filtering and the bounded buffer.
// Log text is untrusted; nothing here renders it, and the viewer only ever shows it as text.

export type Stream = 'stdout' | 'stderr' | 'journal' | 'notice';
export type Level = 'error' | 'warn' | 'info' | 'debug' | 'none';

export interface LogLine {
  id: number;
  ts: number;
  stream: Stream;
  text: string;
  level: Level;
}

export type EndReason =
  'source_ended' | 'source_error' | 'agent_offline' | 'server_shutdown' | 'session_expired';

export type Frame =
  | { type: 'line'; ts: number; stream: Exclude<Stream, 'notice'>; text: string }
  | { type: 'notice'; code: string; message: string; dropped: number }
  | { type: 'end'; reason: EndReason; code: string };

export const MAX_FRAME_BYTES = 256 * 1024;
export const MAX_LINE_CHARS = 16_384;
export const BUFFER_LINES = 5_000;
export const MAX_PATTERN_CHARS = 200;
/** Lines longer than this are never run through a user regex. */
export const MAX_REGEX_LINE_CHARS = 2_000;
export const UNIT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,254}$/;

const REASONS: readonly EndReason[] = [
  'source_ended',
  'source_error',
  'agent_offline',
  'server_shutdown',
  'session_expired',
];
const CODE = /^[A-Z][A-Z0-9-]{1,31}$/;

/** Parses one inbound WebSocket message; anything malformed or unknown yields null. */
export function parseFrame(data: unknown): Frame | null {
  if (typeof data !== 'string' || data.length > MAX_FRAME_BYTES) return null;
  let v: unknown;
  try {
    v = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const code = typeof o.code === 'string' && CODE.test(o.code) ? o.code : '';
  switch (o.type) {
    case 'line': {
      if (typeof o.text !== 'string' || typeof o.ts !== 'number' || !Number.isFinite(o.ts))
        return null;
      const stream = o.stream === 'stderr' || o.stream === 'journal' ? o.stream : 'stdout';
      return { type: 'line', ts: o.ts, stream, text: o.text.slice(0, MAX_LINE_CHARS) };
    }
    case 'notice': {
      if (typeof o.message !== 'string') return null;
      const dropped =
        typeof o.dropped === 'number' && Number.isInteger(o.dropped) && o.dropped > 0
          ? o.dropped
          : 0;
      return { type: 'notice', code, message: o.message.slice(0, 500), dropped };
    }
    case 'end': {
      const reason = REASONS.find((r) => r === o.reason);
      return reason ? { type: 'end', reason, code } : null;
    }
    default:
      return null;
  }
}

const NAMES: Record<string, Level> = {
  fatal: 'error',
  panic: 'error',
  crit: 'error',
  critical: 'error',
  emerg: 'error',
  alert: 'error',
  error: 'error',
  err: 'error',
  warn: 'warn',
  warning: 'warn',
  info: 'info',
  notice: 'info',
  debug: 'debug',
  trace: 'debug',
  dbg: 'debug',
};

function normalise(value: unknown): Level {
  return typeof value === 'string' ? (NAMES[value.toLowerCase()] ?? 'none') : 'none';
}

const LOGFMT = /(?:^|\s)(?:level|lvl|severity)=("?)([A-Za-z]+)\1/i;
const KEYWORD = /\b(FATAL|PANIC|CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b/;
const KEYWORD_LOWER = /\b(error|panic|fatal|warning)\b/i;
const SCAN_CHARS = 512;

export function detectLevel(text: string): Level {
  const head = text.slice(0, SCAN_CHARS);
  if (head.startsWith('{') && text.length <= 8_192) {
    try {
      const o: unknown = JSON.parse(text);
      if (typeof o === 'object' && o !== null) {
        const r = o as Record<string, unknown>;
        for (const key of ['level', 'severity', 'lvl']) {
          const level = normalise(r[key]);
          if (level !== 'none') return level;
        }
      }
    } catch {
      // not JSON after all; fall through to the textual heuristics
    }
  }
  const logfmt = LOGFMT.exec(head);
  if (logfmt?.[2]) {
    const level = normalise(logfmt[2]);
    if (level !== 'none') return level;
  }
  const kw = KEYWORD.exec(head);
  if (kw?.[1]) return normalise(kw[1].replace(/^WARNING$/, 'warn'));
  return KEYWORD_LOWER.test(head) ? 'error' : 'none';
}

export interface Filter {
  /** Null when there is nothing to filter by or the pattern is invalid. */
  test: ((line: LogLine) => boolean) | null;
  error: string | null;
}

// Nested quantifiers such as (a+)+ are the classic catastrophic shape; refuse them outright.
const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]/;

export function compileFilter(pattern: string, mode: 'text' | 'regex'): Filter {
  if (pattern === '') return { test: null, error: null };
  if (pattern.length > MAX_PATTERN_CHARS)
    return {
      test: null,
      error: `The pattern is too long (at most ${MAX_PATTERN_CHARS} characters).`,
    };
  if (mode === 'text') {
    const needle = pattern.toLowerCase();
    return {
      test: (l) => l.stream === 'notice' || l.text.toLowerCase().includes(needle),
      error: null,
    };
  }
  if (NESTED_QUANTIFIER.test(pattern))
    return { test: null, error: 'The pattern is too complex (nested repeats are not allowed).' };
  let re: RegExp;
  try {
    re = new RegExp(pattern, 'i');
  } catch {
    return { test: null, error: 'The regular expression is not valid.' };
  }
  return {
    test: (l) =>
      l.stream === 'notice' || (l.text.length <= MAX_REGEX_LINE_CHARS && re.test(l.text)),
    error: null,
  };
}

/** Newest-last line buffer that drops the oldest lines beyond its capacity. */
export class LogBuffer {
  lines: LogLine[] = [];
  dropped = 0;
  #nextId = 1;

  constructor(readonly capacity = BUFFER_LINES) {}

  make(ts: number, stream: Stream, text: string): LogLine {
    return {
      id: this.#nextId++,
      ts,
      stream,
      text,
      level: stream === 'notice' ? 'none' : detectLevel(text),
    };
  }

  push(batch: LogLine[]): void {
    for (const l of batch) this.lines.push(l);
    const over = this.lines.length - this.capacity;
    if (over > 0) {
      this.lines.splice(0, over);
      this.dropped += over;
    }
  }

  clear(): void {
    this.lines = [];
  }
}
