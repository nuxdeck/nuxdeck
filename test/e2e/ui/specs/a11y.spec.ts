// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from '@playwright/test';
import { adminCredentials } from '../helpers/env';
import { expectNoAxeViolations } from '../helpers/axe';
import { firstHostId, setTheme } from '../helpers/session';

// axe in a real browser, WCAG 2.2 AA tags, light and dark themes (NFR-13, docs/08-engineering-spec.md).
// Colour contrast is computed from rendered pixels here, which jsdom cannot do.

const themes = ['light', 'dark'] as const;

const pages: { name: string; path: string }[] = [
  { name: 'Overview', path: '/' },
  { name: 'Checks', path: '/checks' },
  { name: 'Alerts', path: '/alerts' },
  { name: 'Audit', path: '/audit' },
  { name: 'Users', path: '/settings/users' },
  { name: 'Settings', path: '/settings' },
  { name: 'Account', path: '/account' },
  { name: 'Onboarding: add a host', path: '/inventory/add' },
];

async function open(page: Page, path: string): Promise<void> {
  await page.goto(path);
  await expect(page.locator('h1').first()).toBeVisible();
}

test.describe('axe on the main screens', () => {
  test.skip(
    !adminCredentials.email,
    'E2E_ADMIN_EMAIL is not set; the stack provides the admin account',
  );

  for (const theme of themes) {
    test.describe(`${theme} theme`, () => {
      test.beforeEach(async ({ page }) => setTheme(page, theme));

      for (const { name, path } of pages) {
        test(`${name} (${path}) has no WCAG 2.2 AA violations`, async ({ page }) => {
          await open(page, path);
          await expectNoAxeViolations(page, `${name} (${theme})`);
        });
      }

      test(`host item page overview and logs tabs have no WCAG 2.2 AA violations`, async ({
        page,
      }) => {
        const hostId = await firstHostId(page);
        test.skip(
          !hostId,
          'no host is enrolled: the item page and the logs tab need an agent (see README.md)',
        );
        await open(page, `/inventory/hosts/${hostId}`);
        await expectNoAxeViolations(page, `host item page, overview (${theme})`);

        await page.getByRole('tab', { name: 'Logs' }).click();
        await expect(page.getByRole('tab', { name: 'Logs', selected: true })).toBeVisible();
        await expectNoAxeViolations(page, `host item page, logs (${theme})`);
      });
    });
  }
});
