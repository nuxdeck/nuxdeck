// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { oidcInput, splitList, ssoErrorMessage } from './sso';

describe('splitList', () => {
  it('splits on commas and spaces and drops empty entries', () => {
    expect(splitList(' openid, email  profile,, ')).toEqual(['openid', 'email', 'profile']);
    expect(splitList('   ')).toEqual([]);
  });
});

describe('ssoErrorMessage', () => {
  it('names the code and explains known failures', () => {
    expect(ssoErrorMessage('AUTH-OIDC-008')).toContain('(AUTH-OIDC-008)');
    expect(ssoErrorMessage('AUTH-OIDC-008')).toContain('None of your groups');
  });

  it('keeps only the code for unknown values', () => {
    expect(ssoErrorMessage('AUTH-OIDC-099')).toBe(
      'Single sign-on did not complete. (AUTH-OIDC-099)',
    );
  });
});

describe('oidcInput', () => {
  const base = {
    issuer: ' https://idp.example ',
    clientId: 'nux',
    clientSecret: '',
    scopes: 'openid email',
    groupsClaim: 'groups',
    allowedDomains: 'example.com, example.org',
    autoProvision: true,
    linkExisting: false,
  };

  it('omits the secret when the field is blank, so the stored one is kept', () => {
    const input = oidcInput(base);
    expect(input).not.toHaveProperty('client_secret');
    expect(input.issuer).toBe('https://idp.example');
    expect(input.allowed_domains).toEqual(['example.com', 'example.org']);
  });

  it('sends a typed secret', () => {
    expect(oidcInput({ ...base, clientSecret: 'new' }).client_secret).toBe('new');
  });
});
