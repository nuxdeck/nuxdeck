// SPDX-License-Identifier: AGPL-3.0-only

// Fails the build if the page needs anything the strict Content Security
// Policy forbids: inline script or style, inline handlers, or other origins.
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
const problems = [];

for (const [, attrs, body] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  if (!/\bsrc=/.test(attrs) || body.trim() !== '') problems.push('inline <script>');
}
const rules = [
  [/<style\b/i, 'inline <style>'],
  [/\sstyle\s*=/i, 'inline style attribute'],
  [/\son[a-z]+\s*=/i, 'inline event handler'],
  [/javascript:/i, 'javascript: URL'],
  [/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i, 'reference to another origin'],
];
for (const [re, label] of rules) if (re.test(html)) problems.push(label);

if (problems.length > 0) {
  console.error(
    `dist/index.html violates the Content Security Policy: ${[...new Set(problems)].join(', ')}`,
  );
  process.exit(1);
}
console.log('dist/index.html satisfies the Content Security Policy');
