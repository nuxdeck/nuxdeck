// SPDX-License-Identifier: AGPL-3.0-only

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

// Vitest runs from the web/ directory.
const srcDir = join(process.cwd(), 'src');

function sources(): { path: string; text: string }[] {
  return (readdirSync(srcDir, { recursive: true }) as string[])
    .filter((p) => /\.(svelte|ts|css)$/.test(p) && !p.endsWith('.test.ts'))
    .map((p) => ({
      path: relative(srcDir, join(srcDir, p)),
      text: readFileSync(join(srcDir, p), 'utf8'),
    }));
}

function offenders(files: { path: string; text: string }[], re: RegExp): string[] {
  return files.filter((f) => re.test(f.text)).map((f) => f.path);
}

describe('source policy (docs/08-engineering-spec.md, docs/04-security.md)', () => {
  const all = sources();
  const svelte = all.filter((f) => f.path.endsWith('.svelte'));

  it('finds the sources it is meant to check', () => {
    expect(svelte.length).toBeGreaterThan(5);
  });

  it('never injects HTML', () => {
    expect(offenders(svelte, /\{@html\b/)).toEqual([]);
  });

  it('uses no inline style attributes, which the CSP blocks', () => {
    expect(offenders(svelte, /\sstyle\s*=/)).toEqual([]);
  });

  it('takes every colour from design tokens', () => {
    const files = all.filter((f) => !['lib/ui/tokens.css', 'lib/ui/icons.ts'].includes(f.path));
    expect(offenders(files, /#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/)).toEqual([]);
  });

  it('loads nothing from other origins', () => {
    expect(
      offenders(svelte.concat(all.filter((f) => f.path.endsWith('.css'))), /https?:\/\/|@import/),
    ).toEqual([]);
  });

  // TEMPORARY: the generated client (NUX-40) replaces lib/api/client.ts, the only file allowed to call fetch.
  it('calls the API only through the one client module', () => {
    expect(offenders(all, /\bfetch\(/)).toEqual(['lib/api/client.ts']);
  });
});
