// SPDX-License-Identifier: AGPL-3.0-only

export type Tags = Record<string, string>;

/** The environment of an item is its `env` tag (docs/08-engineering-spec.md, item_tags). */
export const ENV_KEY = 'env';

export const tagText = (tags: Tags): string[] =>
  Object.entries(tags)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}:${v}`);

/** Every distinct `key:value` among the given tag sets, sorted. */
export function tagOptions(sets: Tags[]): string[] {
  return [...new Set(sets.flatMap(tagText))].sort((a, b) => a.localeCompare(b));
}

/** True when `tags` has the `key:value` selector (or the key, if the selector has no value). */
export function hasTag(tags: Tags, selector: string): boolean {
  const [key, ...rest] = selector.split(':');
  const value = rest.join(':');
  if (!key || !(key in tags)) return false;
  return value === '' || tags[key] === value;
}

export interface Group<T> {
  /** The environment, or '' for items without one. */
  env: string;
  items: T[];
}

/** Splits items by environment, named environments first (A to Z), the rest last. Order inside a group is kept. */
export function groupByEnv<T>(items: T[], env: (item: T) => string): Group<T>[] {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = env(item);
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)))
    .map(([env, items]) => ({ env, items }));
}
