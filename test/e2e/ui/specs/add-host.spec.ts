// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test';
import { adminCredentials } from '../helpers/env';
import { setTheme } from '../helpers/session';

// "Add a host" shows the one-line install command with its single-use token (INS-4), and the copy
// button puts exactly that text on the clipboard (WCAG 2.5.3 and 4.1.2 for the button's name).

test.describe('Add a host screen', () => {
  test.skip(
    !adminCredentials.email,
    'E2E_ADMIN_EMAIL is not set; the stack provides the admin account',
  );
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

  test.beforeEach(async ({ page }) => {
    await setTheme(page, 'light');
  });

  test('shows the token inside the install command and copies it', async ({ page }) => {
    await page.goto('/inventory/add');
    await expect(page.getByRole('heading', { name: 'Add a host', level: 1 })).toBeVisible();

    await page.getByRole('button', { name: 'Create token' }).click();
    const command = page.locator('#install-command');
    await expect(command).toContainText(
      'curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --agent --token',
    );
    await expect(command).toContainText('nuxtok1.');
    await expect(page.getByRole('button', { name: 'Create a new token' })).toBeVisible();
    const shown = (await command.textContent())?.trim() ?? '';

    await page.getByRole('button', { name: 'Copy command' }).click();
    await expect(page.getByText('Copied to the clipboard.')).toBeVisible();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied).toBe(shown);
  });
});
