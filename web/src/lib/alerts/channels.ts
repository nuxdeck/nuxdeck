// SPDX-License-Identifier: AGPL-3.0-only

import type { Channel, ChannelInput, ChannelType } from '../api/client';
import { newSecret, secretPayload, type HeaderDraft, type SecretDraft } from '../checks/form';

export const CHANNEL_TYPES: readonly { id: ChannelType; label: string }[] = [
  { id: 'smtp', label: 'E-mail (SMTP)' },
  { id: 'slack', label: 'Slack' },
  { id: 'teams', label: 'Microsoft Teams' },
  { id: 'discord', label: 'Discord' },
  { id: 'telegram', label: 'Telegram' },
  { id: 'webhook', label: 'Webhook' },
];

export const typeLabel = (t: string): string => CHANNEL_TYPES.find((x) => x.id === t)?.label ?? t;

export const SMTP_SECURITY = [
  { value: 'starttls', label: 'STARTTLS (port 587)' },
  { value: 'tls', label: 'TLS (port 465)' },
  { value: 'none', label: 'None (port 25, no sign-in)' },
];

export interface ChannelForm {
  name: string;
  type: ChannelType;
  enabled: boolean;
  allowPrivate: boolean;
  smtp: {
    host: string;
    port: string;
    security: string;
    username: string;
    password: SecretDraft;
    from: string;
    to: string;
  };
  /** The write-only URL of slack, teams, discord and webhook channels. */
  url: SecretDraft;
  telegram: { botToken: SecretDraft; chatId: string };
  headers: HeaderDraft[];
}

export type ChannelErrors = Record<string, string>;

export const emptyChannelForm = (): ChannelForm => ({
  name: '',
  type: 'slack',
  enabled: true,
  allowPrivate: false,
  smtp: {
    host: '',
    port: '',
    security: 'starttls',
    username: '',
    password: newSecret(),
    from: '',
    to: '',
  },
  url: newSecret(),
  telegram: { botToken: newSecret(), chatId: '' },
  headers: [],
});

const isSet = (v: unknown): boolean =>
  typeof v === 'object' && v !== null && (v as { set?: unknown }).set === true;

const text = (v: unknown): string => (typeof v === 'string' ? v : '');

/** Fills the editor from a stored channel. Secrets are never in the response, only whether they are set. */
export function formFromChannel(c: Channel): ChannelForm {
  const f = emptyChannelForm();
  const cfg = c.config ?? {};
  f.name = c.name;
  f.type = c.type;
  f.enabled = c.enabled;
  f.allowPrivate = c.allow_private;
  f.url = newSecret(isSet(cfg.url));
  if (c.type === 'smtp') {
    f.smtp = {
      host: text(cfg.host),
      port: cfg.port === undefined ? '' : String(cfg.port),
      security: text(cfg.security) || 'starttls',
      username: text(cfg.username),
      password: newSecret(isSet(cfg.password)),
      from: text(cfg.from),
      to: Array.isArray(cfg.to) ? cfg.to.map(String).join('\n') : '',
    };
  }
  if (c.type === 'telegram') {
    f.telegram = { botToken: newSecret(isSet(cfg.bot_token)), chatId: text(cfg.chat_id) };
  }
  if (c.type === 'webhook' && Array.isArray(cfg.headers)) {
    f.headers = (cfg.headers as Record<string, unknown>[]).map((h) => ({
      name: text(h.name),
      secret: h.secret === true,
      value: h.secret === true ? '' : text(h.value),
      secretValue: newSecret(isSet(h.secret_value)),
    }));
  }
  return f;
}

const EMAIL = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;

export const recipients = (s: string): string[] =>
  s
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);

/** A secret needs a value: one already stored and kept, or a new one typed. */
const missing = (d: SecretDraft): boolean => (d.clear || !d.wasSet) && d.input === '';

export function validateChannel(f: ChannelForm): ChannelErrors {
  const e: ChannelErrors = {};
  const name = f.name.trim();
  if (name === '' || [...name].length > 100) e.name = 'Give a name of 1 to 100 characters.';
  switch (f.type) {
    case 'smtp': {
      const s = f.smtp;
      if (s.host.trim() === '') e['config.host'] = 'Enter the mail server host name.';
      if (s.port.trim() !== '') {
        const p = /^\d{1,5}$/.test(s.port.trim()) ? Number(s.port) : 0;
        if (p < 1 || p > 65535) e['config.port'] = 'Use a port from 1 to 65535.';
      }
      if (s.username.trim() !== '' && s.security === 'none') {
        e['config.security'] =
          'Credentials are never sent unencrypted; use STARTTLS or TLS, or remove the user name.';
      }
      if (s.username.trim() !== '' && missing(s.password)) {
        e['config.password'] = 'Enter the password for this user name.';
      }
      if (!EMAIL.test(s.from.trim())) e['config.from'] = 'Use a single e-mail address.';
      const to = recipients(s.to);
      if (to.length < 1 || to.length > 20 || to.some((a) => !EMAIL.test(a))) {
        e['config.to'] = 'Give 1 to 20 recipient e-mail addresses.';
      }
      break;
    }
    case 'telegram':
      if (missing(f.telegram.botToken)) e['config.bot_token'] = 'Enter the bot token.';
      if (!/^(-?\d{1,20}|@[A-Za-z0-9_]{3,64})$/.test(f.telegram.chatId.trim())) {
        e['config.chat_id'] = 'Use a numeric chat ID or @channelname.';
      }
      break;
    default:
      if (missing(f.url)) e['config.url'] = 'Enter the URL.';
      else if (f.url.input !== '' && !/^https?:\/\/\S+$/i.test(f.url.input)) {
        e['config.url'] = 'Use a full URL such as https://example.com/hook.';
      }
  }
  if (f.type === 'webhook') {
    if (f.headers.length > 20) e['config.headers'] = 'Use at most 20 headers.';
    const seen = new Set<string>();
    f.headers.forEach((h, i) => {
      const key = `config.headers[${i}]`;
      const lower = h.name.toLowerCase();
      if (!HEADER_NAME.test(h.name)) e[`${key}.name`] = 'Use letters, digits and hyphens.';
      else if (seen.has(lower)) e[`${key}.name`] = 'Header names must be unique.';
      seen.add(lower);
      const value = h.secret ? h.secretValue.input : h.value;
      if (value.length > 1024 || /[\r\n\0]/.test(value)) {
        e[`${key}.${h.secret ? 'secret_value' : 'value'}`] =
          'Use one line of up to 1024 characters.';
      }
    });
  }
  return e;
}

function withSecret(target: Record<string, unknown>, key: string, d: SecretDraft): void {
  const v = secretPayload(d);
  if (v !== undefined) target[key] = v;
}

function configOf(f: ChannelForm): Record<string, unknown> {
  switch (f.type) {
    case 'smtp': {
      const s = f.smtp;
      const c: Record<string, unknown> = {
        host: s.host.trim(),
        security: s.security,
        username: s.username.trim(),
        from: s.from.trim(),
        to: recipients(s.to),
      };
      if (s.port.trim() !== '') c.port = Number(s.port);
      withSecret(c, 'password', s.password);
      return c;
    }
    case 'telegram': {
      const c: Record<string, unknown> = { chat_id: f.telegram.chatId.trim() };
      withSecret(c, 'bot_token', f.telegram.botToken);
      return c;
    }
    case 'webhook': {
      const c: Record<string, unknown> = {
        headers: f.headers.map((h) => {
          if (!h.secret) return { name: h.name, value: h.value };
          const sv = secretPayload(h.secretValue);
          return sv === undefined
            ? { name: h.name, secret: true }
            : { name: h.name, secret: true, secret_value: sv };
        }),
      };
      withSecret(c, 'url', f.url);
      return c;
    }
    default: {
      const c: Record<string, unknown> = {};
      withSecret(c, 'url', f.url);
      return c;
    }
  }
}

/** Builds the request body. Call only on a form that passed `validateChannel`. */
export function channelInput(f: ChannelForm): ChannelInput {
  return {
    name: f.name.trim(),
    type: f.type,
    enabled: f.enabled,
    allow_private: f.allowPrivate,
    config: configOf(f),
  };
}

export const channelFieldId = (path: string): string =>
  `chan-${path.replace(/[^A-Za-z0-9]+/g, '-').replace(/-$/, '')}`;

export function lastStatusLabel(c: Pick<Channel, 'last_status'>): string {
  return c.last_status === 'ok'
    ? 'Last send worked'
    : c.last_status === 'failed'
      ? 'Last send failed'
      : 'Never used';
}

/** "Last send failed (ALR-SEND-002)" for the channel list. */
export function lastSendText(c: Pick<Channel, 'last_status' | 'last_error_code'>): string {
  const code = c.last_status === 'failed' && c.last_error_code ? ` (${c.last_error_code})` : '';
  return `${lastStatusLabel(c)}${code}`;
}
