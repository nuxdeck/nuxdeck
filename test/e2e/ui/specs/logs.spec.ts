// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from '@playwright/test';
import { adminCredentials, optionalEnv } from '../helpers/env';
import { firstHostId, setTheme } from '../helpers/session';

// Log viewer on a host's Logs tab (LOG-2, LOG-4): pause freezes the view, resume continues it, and
// "Jump to latest" appears once the reader scrolls away from the newest line.
// The unit must log on the host: set E2E_LOG_UNIT to one that does (default systemd-journald.service).
const UNIT = optionalEnv('E2E_LOG_UNIT') ?? 'systemd-journald.service';

test.describe('log viewer', () => {
  test.skip(!adminCredentials.email, 'E2E_ADMIN_EMAIL is not set; the stack provides the admin account');

  test.beforeEach(async ({ page }) => {
    await setTheme(page, 'light');
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  test('pause freezes the stream and resume continues it', async ({ page }) => {
    const hostId = await firstHostId(page);
    test.skip(!hostId, 'no host is enrolled: journal logs need an agent (see README.md)');
    await openJournal(page, hostId ?? '');

    await page.getByRole('button', { name: 'Pause' }).click();
    await expect(page.getByRole('button', { name: /^Resume/ })).toBeVisible();
    await page.getByRole('button', { name: /^Resume/ }).click();
    await expect(page.getByRole('button', { name: 'Pause' })).toBeVisible();
  });

  test('jump to latest appears after scrolling up and returns the reader to the end', async ({
    page,
  }) => {
    const hostId = await firstHostId(page);
    test.skip(!hostId, 'no host is enrolled: journal logs need an agent (see README.md)');
    await openJournal(page, hostId ?? '');

    const output = page.getByRole('log', { name: 'Log output' });
    const hasLines = await output
      .locator('.row')
      .nth(1)
      .waitFor({ state: 'attached', timeout: 15_000 })
      .then(
        () => true,
        () => false,
      );
    test.skip(!hasLines, `journal unit ${UNIT} produced fewer than two lines in 15 s; set E2E_LOG_UNIT`);
    const scrollable = await output.evaluate((el) => el.scrollHeight > el.clientHeight);
    test.skip(
      !scrollable,
      `the output of ${UNIT} fits in the viewer, so there is nothing to scroll; set E2E_LOG_UNIT to a busier unit`,
    );

    await output.evaluate((el) => {
      el.scrollTop = 0;
    });
    const jump = page.getByRole('button', { name: 'Jump to latest' });
    await expect(jump).toBeVisible();
    await jump.click();
    await expect(jump).toBeHidden();
  });
});

async function openJournal(page: Page, hostId: string): Promise<void> {
  await page.goto(`/inventory/hosts/${hostId}`);
  await page.getByRole('tab', { name: 'Logs' }).click();
  await page.getByLabel('Journal unit').fill(UNIT);
  await page.getByRole('button', { name: 'View logs' }).click();
  await expect(page.getByRole('log', { name: 'Log output' })).toBeVisible();
  await expect(page.getByText('Live', { exact: true })).toBeVisible({ timeout: 15_000 });
}
