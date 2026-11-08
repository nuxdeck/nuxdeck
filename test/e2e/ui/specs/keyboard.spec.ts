// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test';
import { adminCredentials } from '../helpers/env';
import { firstHostId, setTheme } from '../helpers/session';

// Keyboard-only navigation (WCAG 2.1.1, 2.4.3, 2.1.2): the sidebar, the inventory list and the
// item page tabs are reached with Tab, Enter and the arrow keys, never the pointer.

test.describe('keyboard navigation', () => {
  test.skip(!adminCredentials.email, 'E2E_ADMIN_EMAIL is not set; the stack provides the admin account');

  test.beforeEach(async ({ page }) => {
    await setTheme(page, 'light');
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  test('a sidebar link opens its page with Enter, and focus lands on the heading', async ({
    page,
  }) => {
    await page.goto('/');
    await expect(page.locator('h1').first()).toBeVisible();
    const inventory = page.getByRole('link', { name: 'Inventory' }).first();
    await inventory.focus();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/inventory$/);
    await expect(page.locator('h1#page-title')).toBeFocused();
  });

  test('the inventory table can be reached and walked with Tab', async ({ page }) => {
    const hostId = await firstHostId(page);
    test.skip(!hostId, 'no host is enrolled: the inventory table has no rows (see README.md)');
    await page.goto('/inventory');
    await expect(page.locator('h1#page-title')).toBeVisible();
    const hostLink = page.locator(`a[href="/inventory/hosts/${hostId}"]`);
    await expect(hostLink).toBeVisible();

    // Tab from the heading until the host link has focus; the bound keeps a regression finite.
    await page.locator('h1#page-title').focus();
    for (let i = 0; i < 60 && !(await hostLink.evaluate((el) => el === document.activeElement)); i++) {
      await page.keyboard.press('Tab');
    }
    await expect(hostLink).toBeFocused();
  });

  test('item page tabs: arrow keys move between tabs and Tab leaves the tab list', async ({
    page,
  }) => {
    const hostId = await firstHostId(page);
    test.skip(!hostId, 'no host is enrolled: item pages need an agent (see README.md)');
    await page.goto(`/inventory/hosts/${hostId}`);
    const overview = page.getByRole('tab', { name: 'Overview' });
    await expect(overview).toBeVisible();
    await overview.focus();

    await page.keyboard.press('ArrowRight');
    const metrics = page.getByRole('tab', { name: 'Metrics' });
    await expect(metrics).toBeFocused();
    await expect(metrics).toHaveAttribute('aria-selected', 'true');

    await page.keyboard.press('End');
    await expect(page.getByRole('tab', { name: 'Activity' })).toBeFocused();
    await page.keyboard.press('Home');
    await expect(overview).toBeFocused();
    await expect(overview).toHaveAttribute('aria-selected', 'true');

    // Only the selected tab is in the tab order; Tab moves to the content, not to the next tab.
    await page.keyboard.press('Tab');
    await expect(page.getByRole('tab', { name: 'Metrics' })).not.toBeFocused();
  });
});
