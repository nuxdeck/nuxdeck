// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test';
import { adminCredentials } from '../helpers/env';
import { firstHostId, setTheme } from '../helpers/session';

// The command palette is a modal dialog (docs/06-ux.md, WAI-ARIA dialog pattern): focus moves in
// on open, stays inside while open, and returns to the opener on close (WCAG 2.4.3, 2.1.2).

test.describe('command palette', () => {
  test.skip(!adminCredentials.email, 'E2E_ADMIN_EMAIL is not set; the stack provides the admin account');

  test.beforeEach(async ({ page }) => {
    await setTheme(page, 'light');
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/');
    await expect(page.locator('h1').first()).toBeVisible();
  });

  test('Ctrl+K opens the dialog with focus in the search box', async ({ page }) => {
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Command palette' });
    await expect(dialog).toBeVisible();
    await expect(page.getByRole('combobox')).toBeFocused();
  });

  test('a search finds a host, the arrow keys move through results, and Enter opens one', async ({
    page,
  }) => {
    const hostId = await firstHostId(page);
    test.skip(!hostId, 'no host is enrolled: there is nothing to search for (see README.md)');
    const hostname = (await (await page.request.get(`/api/v1/hosts/${hostId}`)).json()).hostname as string;

    await page.keyboard.press('Control+k');
    await page.getByRole('combobox').pressSequentially(hostname);
    const option = page.getByRole('option', { name: new RegExp(hostname) }).first();
    await expect(option).toBeVisible();
    await expect(page.getByRole('combobox')).toHaveAttribute('aria-activedescendant', /palette-option-0/);

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowUp');
    await expect(page.getByRole('combobox')).toHaveAttribute('aria-activedescendant', /palette-option-0/);

    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(new RegExp(`/inventory/hosts/${hostId}$`));
    await expect(page.locator('h1#page-title')).toBeFocused();
  });

  test('Tab cycles inside the dialog and never reaches the page behind it', async ({ page }) => {
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Command palette' });
    await expect(dialog).toBeVisible();
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press('Tab');
      const inside = await dialog.evaluate((el) => el.contains(document.activeElement));
      expect(inside, `focus left the dialog on Tab ${i + 1}`).toBeTruthy();
    }
    await page.keyboard.press('Shift+Tab');
    expect(await dialog.evaluate((el) => el.contains(document.activeElement))).toBeTruthy();
  });

  test('Escape closes the dialog and returns focus to the button that opened it', async ({ page }) => {
    const opener = page.getByRole('button', { name: /Search/ });
    await opener.click();
    const dialog = page.getByRole('dialog', { name: 'Command palette' });
    await expect(dialog).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(opener).toBeFocused();
  });
});
