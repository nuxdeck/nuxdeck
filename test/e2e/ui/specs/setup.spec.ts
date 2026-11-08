// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test';
import { setupToken } from '../helpers/env';

// First-run setup wizard (INS-3, INS-4). It only runs against a server that has never been set
// up: the stack's shared server is already set up, so the spec skips there with a reason.

test.use({ storageState: { cookies: [], origins: [] } });

test.describe('setup wizard on a fresh server', () => {
  test.beforeEach(async ({ request }) => {
    const response = await request.get('/api/v1/setup/status');
    const { setup_required: required } = (await response.json()) as { setup_required: boolean };
    test.skip(
      !required,
      'setup is already complete on this server; run this spec against a fresh nuxd (see README.md)',
    );
  });

  test('creates the administrator, sets the address, keeps telemetry off, and ends on Add a host', async ({
    page,
    baseURL,
  }) => {
    const token = setupToken();
    test.skip(!token, 'E2E_SETUP_TOKEN is not set: the wizard needs the first-run token');

    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Set up Nux Deck' })).toBeVisible();
    await page.getByLabel('Setup token').fill(token ?? '');
    await page.getByLabel('Your name').fill('E2E Setup Admin');
    await page.getByLabel('Email').fill('e2e-setup-admin@example.test');
    await page.getByLabel('Password').fill('E2e-Setup-Pass-2026!');
    await page.getByRole('button', { name: 'Create administrator' }).click();

    const title = page.locator('#wizard-step-title');
    await expect(title).toHaveText('Server address');
    await expect(page.getByText(/Step 2 of \d/)).toBeVisible();
    await page.getByLabel('Public address').fill(baseURL ?? '');
    await page.getByRole('button', { name: 'Save and continue' }).click();

    await expect(title).toHaveText('Telemetry');
    await expect(page.getByLabel('Send the daily diagnostic report')).not.toBeChecked();
    await page.getByRole('button', { name: 'Save and continue' }).click();

    await expect(title).toHaveText('Add your first host');
    await expect(page.locator('pre code').first()).toContainText('--agent --token');
    await expect(page.getByRole('button', { name: 'Copy command' })).toBeVisible();
    await page.getByRole('button', { name: 'Finish setup' }).click();
    await expect(page.locator('#wizard-step-title')).toHaveText('Setup is complete');
  });
});
