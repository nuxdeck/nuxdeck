// SPDX-License-Identifier: AGPL-3.0-only

export const MIN_PASSWORD_LENGTH = 12;

export interface PasswordFeedback {
  ok: boolean;
  message: string;
}

/**
 * Live guidance only: the server is the authority and also rejects passwords that
 * appear in breach lists (ACC-1). Length is counted in characters, like the server does.
 */
export function passwordFeedback(password: string): PasswordFeedback {
  const length = [...password].length;
  if (length === 0) {
    return { ok: false, message: `Use at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  if (length < MIN_PASSWORD_LENGTH) {
    const missing = MIN_PASSWORD_LENGTH - length;
    return {
      ok: false,
      message: `${missing} more ${missing === 1 ? 'character' : 'characters'} needed.`,
    };
  }
  return { ok: true, message: 'Long enough. Passwords found in known breaches are rejected.' };
}
