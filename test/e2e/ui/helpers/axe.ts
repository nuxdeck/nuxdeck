// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

/** The WCAG 2.2 AA rule sets: level A and AA of 2.0, 2.1 and 2.2. */
export const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

export interface AxeFinding {
  rule: string;
  impact: string | null | undefined;
  targets: string[];
  help: string;
}

/**
 * Runs axe in the real browser, so colour contrast is computed from rendered pixels and not
 * from tokens. The result lists every violation with its rule, impact and CSS targets.
 */
export async function axeFindings(page: Page): Promise<AxeFinding[]> {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  return results.violations.map((v) => ({
    rule: v.id,
    impact: v.impact,
    help: v.help,
    targets: v.nodes.map((n) => n.target.join(' ')),
  }));
}

/** Fails with a readable list of violations for the page under test. */
export async function expectNoAxeViolations(page: Page, label: string): Promise<void> {
  const findings = await axeFindings(page);
  expect(findings, `axe violations on ${label}`).toEqual([]);
}
