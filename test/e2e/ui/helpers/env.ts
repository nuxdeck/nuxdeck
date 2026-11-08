// SPDX-License-Identifier: Apache-2.0

/** Reads a variable the stack sets; an empty value counts as unset. */
export function optionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

/** Reads a variable that must be set, failing the run with the variable's name. */
export function requiredEnv(name: string): string {
  const value = optionalEnv(name);
  if (!value) {
    throw new Error(`${name} is not set. Run the suite through make e2e, or export it (see README.md).`);
  }
  return value;
}

/** The administrator account the stack creates (E2E_ADMIN_*). Absent values skip signed-in tests. */
export const adminCredentials = {
  get email(): string | undefined {
    return optionalEnv('E2E_ADMIN_EMAIL');
  },
  get password(): string | undefined {
    return optionalEnv('E2E_ADMIN_PASSWORD');
  },
};

/** The first-run setup token, given only when the wizard spec runs against a fresh server. */
export function setupToken(): string | undefined {
  return optionalEnv('E2E_SETUP_TOKEN');
}

/**
 * Signed-in session written by the setup project. It holds a session cookie, so it is gitignored.
 * Relative to the working directory, which is test/e2e/ui for make e2e and npx playwright test.
 */
export const AUTH_STATE = '.auth/admin.json';
