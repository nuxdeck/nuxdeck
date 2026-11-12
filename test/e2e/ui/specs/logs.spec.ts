// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from '@playwright/test';
import { adminCredentials, optionalEnv } from '../helpers/env';
import { firstHostId, setTheme } from '../helpers/session';

// Log viewer on a host's Logs tab (LOG-2, LOG-4): pause freezes the view, resume continues it, and
// "Jump to latest" appears once the reader scrolls away from the newest line.
// The stack's agents run in containers without journald, so the viewer opens the stack's nginx
// container (named <compose project>-nginx-1) when one is inventoried. Against a real host it opens a journal unit: set E2E_LOG_UNIT to one
// that logs on the host (default systemd-journald.service).
const UNIT = optionalEnv('E2E_LOG_UNIT') ?? 'systemd-journald.service';

test.describe('log viewer', () => {
  test.skip(
    !adminCredentials.email,
    'E2E_ADMIN_EMAIL is not set; the stack provides the admin account',
  );

  test.beforeEach(async ({ page }) => {
    await setTheme(page, 'light');
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  test('pause freezes the stream and resume continues it', async ({ page }) => {
    await openLogs(page);

    await page.getByRole('button', { name: 'Pause' }).click();
    await expect(page.getByRole('button', { name: /^Resume/ })).toBeVisible();
    await page.getByRole('button', { name: /^Resume/ }).click();
    await expect(page.getByRole('button', { name: 'Pause' })).toBeVisible();
  });

  test('jump to latest appears after scrolling up and returns the reader to the end', async ({
    page,
  }) => {
    await openLogs(page);

    const output = page.getByRole('log', { name: 'Log output' });
    const hasLines = await output
      .locator('.row')
      .nth(1)
      .waitFor({ state: 'attached', timeout: 15_000 })
      .then(
        () => true,
        () => false,
      );
    test.skip(
      !hasLines,
      'the log source produced fewer than two lines in 15 s; set E2E_LOG_UNIT or inventory a busier container',
    );
    const scrollable = await output.evaluate((el) => el.scrollHeight > el.clientHeight);
    test.skip(
      !scrollable,
      'the log output fits in the viewer, so there is nothing to scroll; set E2E_LOG_UNIT to a busier unit',
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

/** Opens a live log source: the nginx container if inventoried, else the host's journal unit. */
async function openLogs(page: Page): Promise<void> {
  const containerId = await runningContainerId(page, /^nux-e2e-[0-9a-f]+-nginx-1$/);
  if (containerId) {
    await page.goto(`/inventory/containers/${containerId}`);
    await page.getByRole('tab', { name: 'Logs' }).click();
  } else {
    const hostId = await firstHostId(page);
    test.skip(!hostId, 'no host is enrolled: logs need an agent (see README.md)');
    await page.goto(`/inventory/hosts/${hostId ?? ''}`);
    await page.getByRole('tab', { name: 'Logs' }).click();
    await page.getByLabel('Journal unit').fill(UNIT);
    await page.getByRole('button', { name: 'View logs' }).click();
  }
  await expect(page.getByRole('log', { name: 'Log output' })).toBeVisible();
  await expect(page.getByText('Live', { exact: true })).toBeVisible({ timeout: 15_000 });
}

async function runningContainerId(page: Page, name: RegExp): Promise<string | undefined> {
  const response = await page.request.get('/api/v1/containers');
  expect(response.ok(), 'GET /api/v1/containers').toBeTruthy();
  const body = (await response.json()) as { items: { id: string; name: string; state: string }[] };
  return body.items.find((c) => name.test(c.name) && c.state === 'running')?.id;
}
