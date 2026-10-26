// SPDX-License-Identifier: AGPL-3.0-only

import { logSocketUrl, probeLogStream } from './api/client';
import { BUFFER_LINES, LogBuffer, parseFrame, type EndReason, type LogLine } from './logs';

export type StreamState = 'idle' | 'connecting' | 'live' | 'ended' | 'error';

export const MAX_RETRIES = 3;
const BACKOFF_MS = [1_000, 2_000, 4_000];

const END_TEXT: Record<EndReason, string> = {
  source_ended: 'The log source ended.',
  source_error: 'The log source reported an error.',
  agent_offline: 'The host went offline.',
  server_shutdown: 'The server is shutting down.',
  session_expired: 'Your session expired. Sign in again.',
};

const schedule: (cb: () => void) => void =
  typeof requestAnimationFrame === 'function'
    ? (cb) => requestAnimationFrame(() => cb())
    : (cb) => void setTimeout(cb, 16);

/** One live log connection plus its bounded buffer; the viewer renders from `buffer.lines`. */
export class LogStream {
  state = $state<StreamState>('idle');
  /** Bumped whenever the buffer or the unseen counter changes. */
  version = $state(0);
  paused = $state(false);
  unseen = $state(0);
  statusText = $state('');
  errorCode = $state('');
  errorHint = $state('');
  retry = $state(0);

  readonly buffer = new LogBuffer(BUFFER_LINES);
  #held: LogLine[] = [];
  #incoming: LogLine[] = [];
  #queued = false;
  #socket: WebSocket | null = null;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #ended = false;
  #opened = false;
  #generation = 0;
  #target = '';
  #tail = 100;

  connect(target: string, tail = 100): void {
    this.close();
    this.#target = target;
    this.#tail = tail;
    this.retry = 0;
    this.#open(tail);
  }

  /** Manual reconnect: a fresh attempt counter, and the original tail. */
  reconnect(): void {
    if (this.#target) this.connect(this.#target, this.#tail);
  }

  close(): void {
    this.#generation++;
    clearTimeout(this.#timer);
    const s = this.#socket;
    this.#socket = null;
    if (s) {
      s.onopen = s.onmessage = s.onerror = s.onclose = null;
      s.close();
    }
  }

  pause(): void {
    this.paused = true;
    this.#announce('Paused. New lines are held back.');
  }

  resume(): void {
    this.paused = false;
    const held = this.#held;
    this.#held = [];
    this.unseen = 0;
    this.buffer.push(held);
    this.version++;
    this.#announce('Resumed.');
  }

  clear(): void {
    this.buffer.clear();
    this.#held = [];
    this.#incoming = [];
    this.unseen = 0;
    this.version++;
  }

  /** Moves queued lines into the buffer; runs once per animation frame, exposed for tests. */
  flush(): void {
    this.#queued = false;
    if (this.#incoming.length === 0) return;
    const batch = this.#incoming;
    this.#incoming = [];
    if (this.paused) {
      this.#held.push(...batch);
      const over = this.#held.length - this.buffer.capacity;
      if (over > 0) this.#held.splice(0, over);
      this.unseen = this.#held.length;
    } else {
      this.buffer.push(batch);
    }
    this.version++;
  }

  #announce(text: string): void {
    this.statusText = text;
  }

  #enqueue(line: LogLine): void {
    this.#incoming.push(line);
    // A flood between frames must not grow without bound either.
    if (this.#incoming.length > this.buffer.capacity * 2)
      this.#incoming.splice(0, this.buffer.capacity);
    if (!this.#queued) {
      this.#queued = true;
      schedule(() => this.flush());
    }
  }

  #query(tail: number): string {
    return `target=${encodeURIComponent(this.#target)}&tail=${tail}`;
  }

  #open(tail: number): void {
    const gen = ++this.#generation;
    this.state = 'connecting';
    this.errorCode = this.errorHint = '';
    this.#ended = false;
    this.#opened = false;
    this.#announce(this.retry > 0 ? `Reconnecting, attempt ${this.retry}.` : 'Connecting.');
    const query = this.#query(tail);
    let socket: WebSocket;
    try {
      socket = new WebSocket(logSocketUrl(query));
    } catch {
      this.#fail('LOG-CLIENT', 'The browser could not open a WebSocket.', 'Reload the page.');
      return;
    }
    this.#socket = socket;
    socket.onopen = () => {
      if (gen !== this.#generation) return;
      this.#opened = true;
      this.state = 'live';
      this.#announce('Live.');
    };
    socket.onmessage = (ev: MessageEvent) => {
      if (gen === this.#generation) this.#onFrame(ev.data);
    };
    socket.onclose = () => {
      if (gen !== this.#generation) return;
      this.#socket = null;
      if (this.#ended) return;
      void this.#dropped(gen, query);
    };
  }

  #onFrame(data: unknown): void {
    const f = parseFrame(data);
    if (!f) return;
    if (f.type === 'line') {
      this.#enqueue(this.buffer.make(f.ts, f.stream, f.text));
    } else if (f.type === 'notice') {
      const suffix = f.dropped > 0 ? ` (${f.dropped} lines dropped)` : '';
      const text = `${f.code ? `${f.code}: ` : ''}${f.message}${suffix}`;
      this.#enqueue(this.buffer.make(Date.now(), 'notice', text));
      this.#announce(text);
    } else {
      this.#ended = true;
      this.flush();
      const reason = END_TEXT[f.reason];
      this.state = 'ended';
      this.errorCode = f.code;
      this.#announce(f.code ? `Ended. ${reason} (${f.code})` : `Ended. ${reason}`);
    }
  }

  async #dropped(gen: number, query: string): Promise<void> {
    if (!this.#opened) {
      // The handshake was refused; the browser hides why, so ask once over plain HTTP.
      const refusal = await probeLogStream(query);
      if (gen !== this.#generation) return;
      if (refusal && refusal.status >= 401 && refusal.status !== 0) {
        this.#fail(refusal.code, refusal.message, refusal.hint);
        return;
      }
    }
    if (this.retry >= MAX_RETRIES) {
      this.#fail(
        'NETWORK',
        'The connection to the server was lost.',
        'Check your connection, then reconnect.',
      );
      return;
    }
    const delay = BACKOFF_MS[this.retry] ?? 4_000;
    this.retry++;
    this.state = 'connecting';
    this.#announce(`Connection lost. Retrying in ${delay / 1000} seconds.`);
    // tail=0 on retries: the lines before the drop are already in the buffer.
    this.#timer = setTimeout(() => {
      if (gen === this.#generation) this.#open(0);
    }, delay);
  }

  #fail(code: string, message: string, hint: string): void {
    this.state = 'error';
    this.errorCode = code;
    this.errorHint = hint;
    this.#announce(`Error ${code}: ${message} ${hint}`);
  }
}
