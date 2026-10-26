// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const css = readFileSync(join(process.cwd(), 'src/lib/ui/tokens.css'), 'utf8');

function declarations(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [, name, value] of block.matchAll(/(--[\w-]+):\s*([^;]+);/g)) {
    out[name as string] = (value as string).trim();
  }
  return out;
}

/** Returns the body of the first `{ ... }` that follows `selector`. */
function blockAfter(selector: string): string {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`selector not found: ${selector}`);
  const open = css.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === '{') depth++;
    if (css[i] === '}' && --depth === 0) return css.slice(open + 1, i);
  }
  throw new Error(`unterminated block: ${selector}`);
}

const light = declarations(blockAfter(':root {'));
const darkByPreference = declarations(blockAfter(":root:not([data-theme='light'])"));
const darkByChoice = declarations(blockAfter(":root[data-theme='dark']"));

function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const channel = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return (
    0.2126 * channel((n >> 16) & 255) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255)
  );
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const textPairs: [string, string][] = [
  ['--color-text', '--color-bg'],
  ['--color-text', '--color-surface'],
  ['--color-text-muted', '--color-bg'],
  ['--color-text-muted', '--color-surface'],
  ['--color-text-muted', '--color-surface-sunken'],
  ['--color-accent', '--color-surface'],
  ['--color-accent', '--color-bg'],
  ['--color-accent-text', '--color-accent'],
  ...['healthy', 'warning', 'critical', 'unknown', 'paused'].map(
    (s) => [`--color-status-${s}`, `--color-status-${s}-bg`] as [string, string],
  ),
];

describe('design tokens', () => {
  it('keeps the two dark copies identical', () => {
    expect(darkByChoice).toEqual(darkByPreference);
  });

  it.each([
    ['light', light],
    ['dark', darkByChoice],
  ])('meets WCAG AA text contrast in the %s theme (1.4.3)', (_name, theme) => {
    for (const [fg, bg] of textPairs) {
      const ratio = contrast(theme[fg] as string, theme[bg] as string);
      expect(ratio, `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each([
    ['light', light],
    ['dark', darkByChoice],
  ])('keeps the focus ring visible in the %s theme (1.4.11)', (_name, theme) => {
    for (const bg of ['--color-bg', '--color-surface']) {
      expect(
        contrast(theme['--color-focus'] as string, theme[bg] as string),
      ).toBeGreaterThanOrEqual(3);
    }
  });

  it.each([
    ['light', light],
    ['dark', darkByChoice],
  ])('keeps chart series visible against the surface in the %s theme (1.4.11)', (_name, theme) => {
    for (let i = 1; i <= 6; i++) {
      expect(
        contrast(theme[`--color-chart-${i}`] as string, theme['--color-surface'] as string),
        `--color-chart-${i}`,
      ).toBeGreaterThanOrEqual(3);
    }
  });

  it('uses the type scale and 4px spacing grid from the UX spec', () => {
    const sizes = ['xs', 'sm', 'base', 'md', 'lg', 'xl'].map((k) => light[`--font-size-${k}`]);
    expect(sizes).toEqual(['12px', '13px', '14px', '16px', '20px', '24px']);
    for (const k of [1, 2, 3, 4, 6]) {
      expect(parseInt(light[`--space-${k}`] as string) % 4).toBe(0);
    }
  });
});
