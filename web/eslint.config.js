// SPDX-License-Identifier: AGPL-3.0-only

import js from '@eslint/js';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'node_modules/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...svelte.configs['flat/recommended'],
  {
    languageOptions: { globals: { ...globals.browser } },
  },
  {
    files: ['**/*.svelte', '**/*.svelte.ts'],
    languageOptions: { parserOptions: { parser: tseslint.parser } },
  },
  {
    files: ['scripts/**/*.mjs', '*.config.js'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    rules: {
      // API data must never be rendered as HTML (docs/08-engineering-spec.md).
      'svelte/no-at-html-tags': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      // Code injection and raw HTML sinks are banned outright (docs/04-security.md, XSS).
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-properties': [
        'error',
        {
          property: 'innerHTML',
          message: 'Render text with Svelte bindings; innerHTML is an XSS sink.',
        },
        {
          property: 'outerHTML',
          message: 'Render text with Svelte bindings; outerHTML is an XSS sink.',
        },
        {
          property: 'insertAdjacentHTML',
          message: 'Render text with Svelte bindings; insertAdjacentHTML is an XSS sink.',
        },
      ],
    },
  },
  {
    // Test files may build DOM fixtures; the source-policy test in src/lib/ui guards app code.
    files: ['**/*.test.ts'],
    rules: { 'no-restricted-properties': 'off' },
  },
);
