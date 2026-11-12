// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { test as setup } from '@playwright/test';
import { AUTH_STATE, adminCredentials } from '../helpers/env';
import { signIn } from '../helpers/session';

// Signs in once and reuses the session. Without admin credentials it writes an empty state, so
// signed-in specs skip with a reason instead of failing the whole run.
setup('sign in as the stack administrator', async ({ page }) => {
  fs.mkdirSync(path.dirname(AUTH_STATE), { recursive: true });
  if (!adminCredentials.email || !adminCredentials.password) {
    fs.writeFileSync(AUTH_STATE, JSON.stringify({ cookies: [], origins: [] }));
    return;
  }
  await signIn(page);
  await page.context().storageState({ path: AUTH_STATE });
});
