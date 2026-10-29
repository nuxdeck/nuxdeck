// SPDX-License-Identifier: AGPL-3.0-only

import type { Rule, RuleInput, RuleKind, Severity } from '../api/client';
import { idsError, parseIds, tagsError } from './model';

// Limits mirror internal/server/alerting/params.go; the server stays the authority.
export interface RuleForm {
  name: string;
  kind: RuleKind;
  severity: Severity;
  enabled: boolean;
  tags: string[];
  ids: string;
  forS: string;
  mode: string;
  restarts: string;
  windowS: string;
  target: string;
  metric: string;
  threshold: string;
  days: string;
}

export type RuleErrors = Record<string, string>;

export const emptyRuleForm = (): RuleForm => ({
  name: '',
  kind: 'check_down',
  severity: 'warning',
  enabled: true,
  tags: [],
  ids: '',
  forS: '',
  mode: 'either',
  restarts: '3',
  windowS: '600',
  target: 'host',
  metric: 'cpu',
  threshold: '90',
  days: '14',
});

const str = (v: unknown, fallback = ''): string =>
  v === undefined || v === null ? fallback : String(v);

export function formFromRule(r: Rule): RuleForm {
  const f = emptyRuleForm();
  const p = r.params ?? {};
  f.name = r.name;
  f.kind = r.kind;
  f.severity = r.severity;
  f.enabled = r.enabled;
  f.tags = [...r.selector.tags];
  f.ids = r.selector.ids.join('\n');
  f.forS = str(p.for_s);
  f.mode = str(p.mode, 'either');
  f.restarts = str(p.restarts, '3');
  f.windowS = str(p.window_s, '600');
  f.target = str(p.target, 'host');
  f.metric = str(p.metric, 'cpu');
  f.threshold = str(p.threshold, '90');
  f.days = str(p.days, '14');
  return f;
}

const wholeNumber = (s: string): number | null => (/^\d{1,9}$/.test(s.trim()) ? Number(s) : null);
const inRange = (n: number | null, lo: number, hi: number): n is number =>
  n !== null && n >= lo && n <= hi;

export function validateRule(f: RuleForm): RuleErrors {
  const e: RuleErrors = {};
  const name = f.name.trim();
  if (name === '' || [...name].length > 100) e.name = 'Give a name of 1 to 100 characters.';
  const tags = tagsError(f.tags);
  if (tags) e['selector.tags'] = tags;
  const ids = idsError(parseIds(f.ids));
  if (ids) e['selector.ids'] = ids;
  if (f.forS.trim() !== '' && !inRange(wholeNumber(f.forS), 0, 86400)) {
    e['params.for_s'] = 'Use 0 to 86400 seconds, or leave blank for the default.';
  }
  switch (f.kind) {
    case 'container_stopped':
      if (!['stopped', 'restart_loop', 'either'].includes(f.mode)) {
        e['params.mode'] = 'Use stopped, restart_loop or either.';
      }
      if (f.mode !== 'stopped') {
        if (!inRange(wholeNumber(f.restarts), 2, 100))
          e['params.restarts'] = 'Use 2 to 100 restarts.';
        if (!inRange(wholeNumber(f.windowS), 60, 3600)) {
          e['params.window_s'] = 'Use 60 to 3600 seconds.';
        }
      }
      break;
    case 'metric_threshold': {
      if (f.target !== 'host' && f.target !== 'container')
        e['params.target'] = 'Use host or container.';
      if (!['cpu', 'memory', 'disk'].includes(f.metric))
        e['params.metric'] = 'Use cpu, memory or disk.';
      else if (f.metric === 'disk' && f.target !== 'host') {
        e['params.metric'] = 'Disk usage is only available for hosts.';
      }
      const t = Number(f.threshold);
      if (f.threshold.trim() === '' || !Number.isFinite(t) || t <= 0 || t > 100) {
        e['params.threshold'] = 'Use a percentage above 0 and up to 100.';
      }
      break;
    }
    case 'tls_expiring':
      if (!inRange(wholeNumber(f.days), 1, 825)) e['params.days'] = 'Use 1 to 825 days.';
      break;
  }
  return e;
}

function paramsOf(f: RuleForm): Record<string, unknown> {
  const p: Record<string, unknown> = {};
  switch (f.kind) {
    case 'container_stopped':
      p.mode = f.mode;
      if (f.mode !== 'stopped') {
        p.restarts = Number(f.restarts);
        p.window_s = Number(f.windowS);
      }
      break;
    case 'metric_threshold':
      p.target = f.target;
      p.metric = f.metric;
      p.threshold = Number(f.threshold);
      break;
    case 'tls_expiring':
      p.days = Number(f.days);
      break;
  }
  if (f.forS.trim() !== '') p.for_s = Number(f.forS);
  return p;
}

/** Builds the request body. Call only on a form that passed `validateRule`. */
export function ruleInput(f: RuleForm): RuleInput {
  return {
    name: f.name.trim(),
    kind: f.kind,
    severity: f.severity,
    enabled: f.enabled,
    selector: { tags: [...f.tags], ids: parseIds(f.ids) },
    params: paramsOf(f),
  };
}

export const ruleFieldId = (path: string): string =>
  `rule-${path.replace(/[^A-Za-z0-9]+/g, '-').replace(/-$/, '')}`;
