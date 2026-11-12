// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test';
import { adminCredentials } from '../helpers/env';
import { signIn } from '../helpers/session';

// These specs start signed out; the shared session from the setup project is not used.
test.use({ storageState: { cookies: [], origins: [] } });

test.describe('sign-in and sign-out (INS-3, NFR-13)', () => {
  test.skip(
    !adminCredentials.email,
    'E2E_ADMIN_EMAIL is not set; the stack provides the admin account',
  );

  test('a wrong password shows an alert and stays on the sign-in form', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel('Email').fill(adminCredentials.email ?? '');
    await page.getByLabel('Password').fill('not-the-password-0000');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert')).toContainText(/incorrect/i);
    await expect(page.getByRole('heading', { name: 'Sign in to Nux Deck' })).toBeVisible();
  });

  test('signs in, then signs out back to the sign-in form', async ({ page }) => {
    await signIn(page);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('heading', { name: 'Sign in to Nux Deck' })).toBeVisible();

    await page.goto('/inventory');
    await expect(page.getByRole('heading', { name: 'Sign in to Nux Deck' })).toBeVisible();
  });
});
