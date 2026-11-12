// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from '@playwright/test';
import { AUTH_STATE, requiredEnv } from './helpers/env';

// The Compose stack (test/e2e) starts nuxd and writes these variables to test/e2e/.stack/env.
// This config starts nothing itself; it only drives the server it is pointed at.
const baseURL = requiredEnv('E2E_BASE_URL');

export default defineConfig({
  testDir: './specs',
  outputDir: './test-results',
  // One worker: specs share one server, one admin account and its sign-in rate limits.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { outputFolder: 'playwright-report', open: 'never' }]],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    // nuxd serves a self-signed certificate or one from the stack's private CA. Playwright cannot
    // load a CA into the browser, so certificate errors are ignored for this test origin only.
    ignoreHTTPSErrors: true,
    locale: 'en-GB',
    timezoneId: 'UTC',
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      name: 'chromium',
      dependencies: ['setup'],
      testIgnore: /auth\.setup\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: AUTH_STATE },
    },
  ],
});
