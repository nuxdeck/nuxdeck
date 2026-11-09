# Browser tests (test/e2e/ui)

Playwright end-to-end and accessibility checks for the nuxd web UI, run in Chromium. Licence:
Apache-2.0. This package is separate from `web/`, so the app's dependencies stay unchanged.

## Run

`make e2e` runs `npm ci && npx playwright test` here with the stack's variables. To run by hand
against a server that is already running:

| Variable             | Use                                                                             |
| -------------------- | ------------------------------------------------------------------------------- |
| `E2E_BASE_URL`       | Required. For example `https://127.0.0.1:8443`. Certificate errors are ignored. |
| `E2E_ADMIN_EMAIL`    | Administrator account. Without it, signed-in specs skip with a reason.          |
| `E2E_ADMIN_PASSWORD` | Password for that account.                                                      |
| `E2E_SETUP_TOKEN`    | Only for `setup.spec.ts`, against a server that has never been set up.          |
| `E2E_LOG_UNIT`       | Journal unit for the log viewer specs (default `systemd-journald.service`).     |

The run needs at least one enrolled host for the item page, palette search, keyboard and log
specs. Without one those specs skip and say so. `setup.spec.ts` skips unless the server reports
`setup_required: true`.

Run `npm run typecheck` and `npm run lint` before committing. They reuse the TypeScript, ESLint and
Prettier installed in `web/`, so they need no install here.

## Layout

- `specs/auth.setup.ts` signs in once and saves `.auth/admin.json` (gitignored: it holds a session).
- `specs/auth.spec.ts`, `specs/setup.spec.ts`, `specs/add-host.spec.ts`: sign-in and sign-out,
  the setup wizard and the install command.
- `specs/keyboard.spec.ts`, `specs/palette.spec.ts`, `specs/logs.spec.ts`: keyboard paths, the
  command palette and the log viewer.
- `specs/layout.spec.ts`: skip link, focus ring, focus on route change, reflow at 320 and 640 CSS
  px, reduced motion and target sizes.
- `specs/a11y.spec.ts`: axe with WCAG 2.2 AA tags on the main pages, in light and dark themes.
- `helpers/`: environment, sign-in and the axe wrapper.

Failing checks are real findings. `web/A11Y-CHECKLIST.md` section 6 lists the open ones.
