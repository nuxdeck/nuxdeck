// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Locator, type Page } from '@playwright/test';
import { adminCredentials } from '../helpers/env';
import { setTheme } from '../helpers/session';

// Checks that need a real layout engine: jsdom does not lay out pages, so these assert on rendered
// geometry, computed styles and focus in Chromium (WCAG 2.2 2.4.1, 2.4.3, 2.4.7, 1.4.10, 1.4.4,
// 2.2.2, 2.5.8).

const routes = [
  '/',
  '/inventory',
  '/checks',
  '/alerts',
  '/status-pages',
  '/settings',
  '/audit',
  '/account',
  '/settings/users',
  '/inventory/add',
];

/** Pixels the page is wider than its viewport, with the elements that stick out past the edge. */
async function horizontalOverflow(page: Page): Promise<{ overflow: number; offenders: string[] }> {
  return page.evaluate(() => {
    const root = document.documentElement;
    const edge = root.clientWidth;
    const offenders = [...document.querySelectorAll('body *')]
      .filter((el) => el.getBoundingClientRect().right > edge + 1)
      .slice(0, 5)
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${String(el.getAttribute('class') ?? '').split(' ')[0]}`,
      );
    return { overflow: root.scrollWidth - edge, offenders };
  });
}

async function open(page: Page, path: string): Promise<void> {
  await page.goto(path);
  await expect(page.locator('h1').first()).toBeVisible();
}

test.describe('layout and focus in Chromium', () => {
  test.skip(
    !adminCredentials.email,
    'E2E_ADMIN_EMAIL is not set; the stack provides the admin account',
  );

  test.beforeEach(async ({ page }) => {
    await setTheme(page, 'light');
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  test('the skip link is the first Tab stop and moves focus into main (2.4.1)', async ({
    page,
  }) => {
    // A fresh page starts with focus on the document, so the first Tab is the first tab stop.
    await open(page, '/');
    await page.keyboard.press('Tab');
    // Checked against document.activeElement: Playwright's toBeFocused reports this off-screen
    // skip link as inactive even while it holds focus (verified with the probe in this file's history).
    const skip = page.getByRole('link', { name: 'Skip to main content' });
    expect(await isActive(skip), 'skip link is the first Tab stop').toBeTruthy();

    await page.keyboard.press('Enter');
    expect(await isActive(page.locator('main#main')), 'focus moved into main').toBeTruthy();
  });

  test('the focused control has a visible focus ring and is not covered (2.4.7, 2.4.11)', async ({
    page,
  }) => {
    await open(page, '/');
    const link = page.getByRole('link', { name: 'Inventory' }).first();
    await link.focus();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    await expect(link).toBeFocused();

    const ring = await link.evaluate((el) => {
      const style = getComputedStyle(el);
      return {
        outlineWidth: parseFloat(style.outlineWidth),
        outlineStyle: style.outlineStyle,
        boxShadow: style.boxShadow,
      };
    });
    const hasOutline = ring.outlineStyle !== 'none' && ring.outlineWidth > 0;
    const hasShadow = ring.boxShadow !== 'none';
    expect(hasOutline || hasShadow, `focus ring: ${JSON.stringify(ring)}`).toBeTruthy();

    // The point at the control's centre must hit the control, not the sticky top bar or a panel.
    const hit = await link.evaluate((el) => {
      const box = el.getBoundingClientRect();
      const top = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
      return top !== null && (top === el || el.contains(top));
    });
    expect(hit, 'the focused link is covered by another element at its centre').toBeTruthy();
  });

  test('a route change moves focus to the page heading (2.4.3)', async ({ page }) => {
    await open(page, '/');
    await page.getByRole('link', { name: 'Inventory' }).first().click();
    await expect(page).toHaveURL(/\/inventory$/);
    await expect(page.locator('h1#page-title')).toBeFocused();
  });

  for (const width of [320, 640]) {
    const label =
      width === 320
        ? '320 CSS px (reflow, WCAG 1.4.10)'
        : '640 CSS px (200% zoom on a 1280 px display)';
    test(`no horizontal page scroll at ${label}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 });
      const failures: string[] = [];
      for (const route of routes) {
        await open(page, route);
        const { overflow, offenders } = await horizontalOverflow(page);
        if (overflow > 0)
          failures.push(`${route}: ${overflow}px wider, e.g. ${offenders.join(', ')}`);
      }
      expect(failures, `pages wider than ${width} CSS px`).toEqual([]);
    });
  }

  test('at 200% zoom the primary controls stay on screen (1.4.4)', async ({ page }) => {
    // Playwright has no browser zoom control. A 1280 CSS px window at 200% zoom is a 640 CSS px
    // layout viewport, so the same layout is produced by setting that viewport width.
    await page.setViewportSize({ width: 640, height: 800 });
    await open(page, '/inventory');
    const controls = [
      page.getByRole('button', { name: 'Toggle sidebar' }),
      page.getByRole('button', { name: 'Search' }),
      page.locator('h1#page-title'),
    ];
    for (const control of controls) {
      await expect(control).toBeVisible();
      const box = await control.boundingBox();
      expect(
        box && box.x >= 0 && box.x + box.width <= 640,
        'control inside the viewport',
      ).toBeTruthy();
    }
  });

  test('the sidebar does not animate when reduced motion is requested (2.3.3)', async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await open(page, '/');
    const sidebar = page.getByRole('navigation', { name: 'Main' });
    expect(await transitionDuration(sidebar)).toBe('0s');

    // The same element animates without the preference, so the check above is meaningful.
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await open(page, '/');
    expect(await transitionDuration(page.getByRole('navigation', { name: 'Main' }))).not.toBe('0s');
  });

  test('icon buttons and links in the top bar and sidebar are at least 24 by 24 px (2.5.8)', async ({
    page,
  }) => {
    await open(page, '/');
    const targets = page.locator(
      'header.topbar button:visible, header.topbar a:visible, nav[aria-label="Main"] a:visible',
    );
    const count = await targets.count();
    expect(count, 'targets found').toBeGreaterThan(5);
    const small: string[] = [];
    for (let i = 0; i < count; i++) {
      const target = targets.nth(i);
      const box = await target.boundingBox();
      const label =
        (await target.getAttribute('aria-label')) ?? (await target.textContent())?.trim();
      if (!box || box.width < 24 || box.height < 24) {
        small.push(
          `${label || '(unnamed)'} ${box ? `${Math.round(box.width)}x${Math.round(box.height)}` : 'hidden'}`,
        );
      }
    }
    expect(small, 'targets smaller than 24 by 24 CSS px').toEqual([]);
  });
});

async function isActive(locator: Locator): Promise<boolean> {
  return locator.evaluate((el) => el === document.activeElement);
}

async function transitionDuration(locator: Locator): Promise<string> {
  return locator.evaluate((el) => getComputedStyle(el).transitionDuration);
}
