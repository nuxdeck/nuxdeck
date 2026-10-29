---
title: Users, roles, sessions and security
description: Accounts, roles and scopes, TOTP and recovery codes, single sign-on, sessions, API tokens and lockout.
weight: 80
---

## Roles

Every grant is a **role binding**: a subject, a role and an optional scope.

| Role       | Can                                                                                                                                                                                           |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `viewer`   | Read inventory, metrics, logs, checks, alerts, rules, silences and status pages. Read the API document.                                                                                       |
| `operator` | Everything a viewer can, plus tags and owners, check changes and runs, alert acknowledgement, rules, silences and status pages.                                                               |
| `admin`    | Everything an operator can, plus agent tokens and revocation, notification channels and routes, users, sessions, settings (including single sign-on), role bindings, audit log and telemetry. |

Any signed-in user can manage their own sessions, API tokens and two-factor settings. Actions that are not in the permission table are denied.

The server keeps at least one enabled unscoped administrator. Removing the last one fails with `AUTH-USER-002`.

## Scopes

A scope limits a binding to some items:

```json
{
  "environments": ["production", "staging"],
  "tag_sets": [["team:payments", "tier:web"], ["team:search"]]
}
```

- `environments` matches the `env` tag.
- Within one tag set every tag must match (AND). Across tag sets any may match (OR).
- An empty or absent scope means everything.
- Unknown fields are rejected. Limits: 32 environments, 32 tag sets, 128 characters per value.
- Scoped bindings never grant access to global resources such as users, settings or channels.

Create a binding with `POST /api/v1/role-bindings`:

```json
{
  "subject_type": "oidc_group",
  "subject": "nux-ops",
  "role": "operator",
  "scope": { "environments": ["staging"] }
}
```

`subject_type` is `user` (the user's ID) or `oidc_group` (the group name from the identity provider). A binding whose stored scope can no longer be read is returned with `"invalid": true` and grants nothing. Deleting the last unscoped admin binding returns `422`.

## Passwords

Passwords must be at least 12 characters (and at most 256 bytes), must not be on the embedded common-password list, and must not equal the email address or its local part. There is no live breached-password lookup in v0.1 (see [Limits](limits.md)). Passwords are stored with Argon2id.

## Two-factor (TOTP)

Enable TOTP in your account: `POST /api/v1/me/totp/enrol` returns the secret and an `otpauth` URI for your authenticator app. Confirm with a code at `POST /api/v1/me/totp/confirm`; the response lists 10 single-use recovery codes, shown once. Store them.

- Codes are 6 digits, 30 seconds, SHA-1, accepting one step either side. A code works once.
- Recovery codes have the form `XXXXX-XXXXX`. Entry ignores case, dashes and spaces.
- Disable TOTP with `POST /api/v1/me/totp/disable`, which needs your password.

When signing in with a password and TOTP is on, `POST /api/v1/auth/login` returns a pending ticket valid for 5 minutes and 5 attempts. Complete it with `POST /api/v1/auth/totp/verify`. If the account must enrol, use `POST /api/v1/auth/totp/enrol`. A failed or expired step returns `AUTH-TOTP-002`; wrong codes return `AUTH-TOTP-001`.

## Single sign-on (OIDC)

Single sign-on uses a generic OIDC issuer. Google, Microsoft and GitHub have no special handling; use their OIDC endpoints as a generic issuer if they provide one, and test first. Settings live in the database, not in the configuration file, and an admin sets them with `PUT /api/v1/settings/oidc` (or in **Settings**).

| Field                        | Meaning                                                                                        |
| ---------------------------- | ---------------------------------------------------------------------------------------------- |
| `issuer`                     | `https` issuer URL. No query or fragment.                                                      |
| `client_id`, `client_secret` | Client credentials. The secret is write-only (`client_secret_set` shows whether it is stored). |
| `scopes`                     | Default `openid email profile`. `openid` is always added; at most 16.                          |
| `groups_claim`               | Claim with group names. Default `groups`.                                                      |
| `allowed_domains`            | Email domains allowed to sign in (at most 20). Empty means any.                                |
| `auto_provision`             | Create an account on first sign-in (default false). Needs a verified email.                    |
| `link_existing`              | Link a sign-in to an existing account with the same verified email (default false).            |

Set `server.public_url` first. The redirect URI is `<public_url>/api/v1/auth/oidc/callback`; register exactly that in the provider.

Flow: `GET /api/v1/auth/oidc/start` uses PKCE (S256), a state and a nonce, valid for 5 minutes. The callback accepts RS256 and ES256 tokens only. It requires `sub`, a matching nonce and a usable `email`. `email_verified` must be true when present, and must be true to link or provision.

Accounts resolve by subject first, then by email only with `link_existing`, otherwise they are created only with `auto_provision`. A user with no role binding is refused (`AUTH-OIDC-008`). Failures redirect to the sign-in page with the code in `sso_error`.

## Sessions

- The session cookie is `__Host-nux_session`: HttpOnly, Secure, SameSite=Strict, path `/`. Only a SHA-256 hash of it is stored.
- Sessions expire after 12 hours idle or 7 days absolute. Activity is recorded at most once a minute.
- Every state-changing browser request needs the `X-CSRF-Token` header from the sign-in response, and must come from the same site (see [REST API](rest-api.md)).
- List and revoke your sessions at `/api/v1/me/sessions`. Admins can list and revoke a user's sessions at `/api/v1/users/{id}/sessions`.

## API tokens

Create a token in your account, or with `POST /api/v1/me/tokens`. The token is shown once and looks like `nuxt_...`. It is stored as a hash.

- Send it as `Authorization: Bearer <token>`. A Bearer token takes precedence over the session cookie, and an invalid one is refused.
- Lifetime at most 365 days; at most 50 per user.
- Session-only actions (password, TOTP, sign-out, sessions) refuse tokens.
- A token can grant only a role and scope its owner holds (`AUTH-TOKEN-002`).

## Lockout and rate limits

| Limit                                              | Result                                              |
| -------------------------------------------------- | --------------------------------------------------- |
| 10 failed sign-ins per address in 5 minutes        | Sign-in from that address blocked (`AUTH-DENY-002`) |
| 5 failures for one email and address in 15 minutes | Account locked for 15 minutes (`AUTH-LOCK-001`)     |
| 5 password or code guesses per user in 15 minutes  | Refused until the window passes                     |
| Enrolment failures per address                     | `GW-RATE-001`                                       |

## Reset a password

An admin can reset a user's password with `POST /api/v1/users/{id}/reset`.
