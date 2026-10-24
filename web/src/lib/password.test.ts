// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { passwordFeedback } from './password';

describe('passwordFeedback', () => {
  it.each([
    ['', false, 'Use at least 12 characters.'],
    ['a', false, '11 more characters needed.'],
    ['abcdefghijk', false, '1 more character needed.'],
    ['abcdefghijkl', true, 'Long enough'],
    ['éééééééééééé', true, 'Long enough'], // 12 characters, 24 bytes
    ['ééééééééééé', false, '1 more character needed.'], // 11 characters
  ])('%j', (password, ok, message) => {
    const fb = passwordFeedback(password);
    expect(fb.ok).toBe(ok);
    expect(fb.message).toContain(message);
  });
});
