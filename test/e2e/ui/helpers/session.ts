// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from '@playwright/test';
import { adminCredentials } from './env';

/** Signs in through the sign-in form and waits for the signed-in shell. */
export async function signIn(page: Page): Promise<void> {
  const email = adminCredentials.email;
  const password = adminCredentials.password;
  if (!email || !password) throw new Error('E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD are required');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Sign in to Nux Deck' })).toBeVisible();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
}

/** Sets the theme before the app starts, so the first paint already uses it. */
export async function setTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
  await page.addInitScript((value) => {
    try {
      window.localStorage.setItem('nux.theme', value);
    } catch {
      /* storage blocked: the page falls back to the system theme */
    }
  }, theme);
}

/** Returns the first host the agent enrolled, or undefined when the server has none. */
export async function firstHostId(page: Page): Promise<string | undefined> {
  const response = await page.request.get('/api/v1/hosts');
  expect(response.ok(), 'GET /api/v1/hosts').toBeTruthy();
  const body = (await response.json()) as { items: { id: string }[] };
  return body.items[0]?.id;
}
