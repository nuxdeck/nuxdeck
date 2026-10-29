// SPDX-License-Identifier: AGPL-3.0-only

import type { OidcInput } from './api/client';

/** Splits a comma- or space-separated field into trimmed, non-empty entries. */
export function splitList(text: string): string[] {
  return text
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

/** Human text for an AUTH-OIDC code returned to the sign-in page. Unknown codes keep the code only. */
export function ssoErrorMessage(code: string): string {
  const known: Record<string, string> = {
    'AUTH-OIDC-002': 'The single sign-on attempt expired. Start it again.',
    'AUTH-OIDC-003': 'The identity provider could not complete the sign-in. Try again.',
    'AUTH-OIDC-004': 'The identity provider token was not accepted.',
    'AUTH-OIDC-005': 'The identity provider did not confirm your email address.',
    'AUTH-OIDC-006': 'Single sign-on is not allowed for your email domain.',
    'AUTH-OIDC-007': 'No account matches this sign-in. Ask an administrator.',
    'AUTH-OIDC-008': 'None of your groups has a role on this server. Ask an administrator.',
    'AUTH-OIDC-009': 'This account is disabled.',
    'AUTH-OIDC-010': 'This email address already belongs to another account.',
  };
  const text = known[code] ?? 'Single sign-on did not complete.';
  return `${text} (${code})`;
}

/** Builds the settings request from the form's text fields. The secret is sent only when typed. */
export function oidcInput(form: {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  groupsClaim: string;
  allowedDomains: string;
  autoProvision: boolean;
  linkExisting: boolean;
}): OidcInput {
  const input: OidcInput = {
    issuer: form.issuer.trim(),
    client_id: form.clientId.trim(),
    scopes: splitList(form.scopes),
    groups_claim: form.groupsClaim.trim(),
    allowed_domains: splitList(form.allowedDomains),
    auto_provision: form.autoProvision,
    link_existing: form.linkExisting,
  };
  if (form.clientSecret !== '') input.client_secret = form.clientSecret;
  return input;
}
