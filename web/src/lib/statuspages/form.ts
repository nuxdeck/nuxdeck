// SPDX-License-Identifier: AGPL-3.0-only

import type { IncidentImpact, IncidentStatus, StatusPage, StatusPageInput } from '../api/client';
import { auth } from '../auth.svelte';

export const SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
export const MAX_TITLE = 100;
export const MAX_DESCRIPTION = 500;
export const MAX_COMPONENT_NAME = 80;
export const MAX_COMPONENTS = 20;
export const MAX_INCIDENT_TITLE = 140;
export const MAX_INCIDENT_BODY = 2000;

export const INCIDENT_STATUSES: { value: IncidentStatus; label: string }[] = [
  { value: 'investigating', label: 'Investigating' },
  { value: 'identified', label: 'Identified' },
  { value: 'monitoring', label: 'Monitoring' },
  { value: 'resolved', label: 'Resolved' },
];

export const INCIDENT_IMPACTS: { value: IncidentImpact; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'minor', label: 'Minor' },
  { value: 'major', label: 'Major' },
];

/** Operators and admins may change status pages; viewers only read. The server enforces it as well. */
export function canWriteStatusPages(): boolean {
  const roles = auth.user?.roles ?? [];
  return roles.includes('operator') || roles.includes('admin');
}

/** A component in the editor; `key` identifies it across moves, it is never sent. */
export interface ComponentForm {
  key: number;
  name: string;
  check_ids: string[];
}

export interface PageForm {
  slug: string;
  title: string;
  description: string;
  published: boolean;
  components: ComponentForm[];
}

export type PageErrors = Record<string, string>;

let nextKey = 1;

export function emptyForm(): PageForm {
  return { slug: '', title: '', description: '', published: false, components: [] };
}

export function newComponent(): ComponentForm {
  return { key: nextKey++, name: '', check_ids: [] };
}

export function formFromPage(p: StatusPage): PageForm {
  return {
    slug: p.slug,
    title: p.title,
    description: p.description,
    published: p.published,
    components: p.components.map((c) => ({
      key: nextKey++,
      name: c.name,
      check_ids: [...c.check_ids],
    })),
  };
}

export function toInput(f: PageForm): StatusPageInput {
  return {
    slug: f.slug,
    title: f.title.trim(),
    description: f.description.trim(),
    published: f.published,
    components: f.components.map((c) => ({ name: c.name.trim(), check_ids: [...c.check_ids] })),
  };
}

// Code point ranges the server refuses: control, soft hyphen, zero-width, bidirectional and BOM.
const HIDDEN_RANGES: readonly (readonly [number, number])[] = [
  [0x00, 0x09],
  [0x0b, 0x1f],
  [0x7f, 0x9f],
  [0xad, 0xad],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x2069],
  [0xfeff, 0xfeff],
];

function hasHidden(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    if (HIDDEN_RANGES.some(([lo, hi]) => c >= lo && c <= hi)) return true;
  }
  return false;
}

export function textProblem(v: string, max: number, required: boolean): string | undefined {
  const t = v.trim();
  if (required && t === '') return 'This field is required.';
  if ([...t].length > max) return `Use at most ${max} characters.`;
  if (hasHidden(t)) return 'Remove control and invisible characters.';
  return undefined;
}

export function fieldId(key: string): string {
  return `sp-${key.replace(/[^a-z0-9]+/gi, '-')}`;
}

/** Mirrors the server's rules so most mistakes show before a request is sent. `creating` checks the slug. */
export function validate(f: PageForm, creating: boolean): PageErrors {
  const e: PageErrors = {};
  if (creating && !SLUG_PATTERN.test(f.slug)) {
    e.slug =
      'Use lowercase letters, digits and hyphens, starting and ending with a letter or digit.';
  } else if (creating && f.slug === 'assets') {
    e.slug = 'This slug is reserved.';
  }
  const title = textProblem(f.title, MAX_TITLE, true);
  if (title) e.title = title;
  const description = textProblem(f.description.replace(/[\r\n]/g, ' '), MAX_DESCRIPTION, false);
  if (description) e.description = description;
  if (f.components.length > MAX_COMPONENTS)
    e.components = `Use at most ${MAX_COMPONENTS} components.`;
  f.components.forEach((c, i) => {
    const name = textProblem(c.name, MAX_COMPONENT_NAME, true);
    if (name) e[`components[${i}].name`] = name;
  });
  return e;
}

/** Moves item `from` to `to`, returning a new array. Out-of-range moves return the input unchanged. */
export function move<T>(list: readonly T[], from: number, to: number): T[] {
  if (from < 0 || to < 0 || from >= list.length || to >= list.length || from === to) {
    return [...list];
  }
  const out = [...list];
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item as T);
  return out;
}

/** The address visitors open. */
export function publicUrl(slug: string): string {
  return `${window.location.origin}/status/${slug}`;
}

/** Maps a server field such as "components[1].check_ids" to the editor's error keys. */
export function serverField(field: string | undefined): string | undefined {
  return field && field !== '' ? field : undefined;
}
