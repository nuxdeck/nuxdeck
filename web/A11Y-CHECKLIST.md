<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Accessibility manual checklist (NUX-48)

Three kinds of automated check exist. Each item below names the one that proves it.

- **Unit (jsdom), `npx vitest run`:** axe on every route and key state (`src/a11y.routes.test.ts`,
  `src/a11y.states.test.ts`, `src/a11y.test.ts`), token contrast and motion tokens
  (`src/lib/ui/tokens.test.ts`). jsdom does not lay out pages, so it cannot see focus rings on
  real pixels, reflow, zoom or target sizes.
- **Browser, `npm run test` in `test/e2e/ui` (Playwright, Chromium):** axe on real rendered pages in
  light and dark themes (`specs/a11y.spec.ts`), and focus, layout, zoom, motion and target checks
  (`specs/layout.spec.ts`), keyboard paths (`specs/keyboard.spec.ts`), the command palette
  (`specs/palette.spec.ts`), the log viewer (`specs/logs.spec.ts`), the Add a host screen
  (`specs/add-host.spec.ts`), sign-in (`specs/auth.spec.ts`) and the setup wizard
  (`specs/setup.spec.ts`, fresh server only).
- **Human:** screen readers and everything no script can judge. Section 2 is open.

Ticked items are proven by a passing browser check. Items marked **FAILS** are proven wrong by a
failing check; the failure is a real defect, not a skipped test. Nothing in this file has been
checked with a screen reader.

**Screen-reader testing has NOT been performed.** Nothing below has been run with NVDA, JAWS or
VoiceOver. Every item in section 2 is still open until a person has checked it.

## 1. Keyboard (any browser, no mouse)

Run on Chrome or Firefox at 100% and 200% zoom, and at 320 px width.

- [x] Tab from the address bar reaches "Skip to main content" first; Enter moves focus into
      `<main>`. Spec: `layout.spec.ts`, "the skip link is the first Tab stop and moves focus into
      main". The link interceptor in `src/lib/ui/Shell.svelte` now leaves in-page `#` links to the
      browser; unit test `src/app.test.ts`, "leaves the skip link to the browser".
- [ ] Every sidebar link, the search button, the user menu, density and theme toggles, and every
      button on each page can be reached and activated with Enter or Space.
  - [x] Sidebar link "Inventory" reached with the keyboard and activated with Enter. Spec:
        `keyboard.spec.ts`, "a sidebar link opens its page with Enter, and focus lands on the heading".
  - [x] Command palette opened with Ctrl+K and closed with Escape. Spec: `palette.spec.ts`.
  - [ ] Every other control on every page. Not automated.
- [ ] The focus ring is visible on every control in light and dark themes (2px `--color-focus`).
  - [x] Light theme, one sidebar link: outline or box-shadow is computed as non-zero. Spec:
        `layout.spec.ts`, "the focused control has a visible focus ring". Dark theme and other
        controls: not automated.
- [ ] The focus ring is not hidden under the sticky top bar or the side panels when tabbing.
  - [x] Light theme, one sidebar link: the element at the link's centre is the link itself
        (`elementFromPoint`). Spec: `layout.spec.ts`, same test. Other controls and panels: not
        automated.
- [ ] Tab order follows the visual order on Account, Audit, Settings, Users, Status pages editor,
      Alerts (all five views), Checks editor, and every setup wizard step. Not automated.
- [ ] Route change (sidebar link, back button) moves focus to the page `<h1>`.
  - [x] Sidebar link click moves focus to `h1#page-title`. Spec: `layout.spec.ts`, "a route change
        moves focus to the page heading". Browser back button: not automated.
- [ ] Command palette (Ctrl/Cmd+K): opens with focus in the search box; arrow keys move through
      results; Enter runs one; Tab stays inside the palette; Escape closes it and focus returns to
      the button that opened it.
  - [x] Opens with focus in the search box. Spec: `palette.spec.ts`, "Ctrl+K opens the dialog".
  - [x] Enter opens the selected host. Spec: `palette.spec.ts`, "a search finds a host ...".
  - [ ] Arrow keys move through results. Only one result is searched, so movement between several
        results is not proven.
  - [x] Tab stays inside the palette for eight presses. Spec: `palette.spec.ts`, "Tab cycles inside
        the dialog".
  - [x] Escape closes it and returns focus to the "Search" button. Spec: `palette.spec.ts`, "Escape
        closes the dialog".
- [ ] Audit detail panel: "Details" opens it and focus moves to its Close button; Escape closes it
      and focus returns to the "Details" button that opened it. Not automated.
- [ ] Tabs (Alerts views): arrow keys move between tabs; Tab leaves the tab list.
  - [x] Item page tabs (host): ArrowRight, End and Home move between tabs, and Tab leaves the tab
        list. Spec: `keyboard.spec.ts`, "item page tabs". Alerts views: not automated.
- [ ] Time-range picker: arrow keys move between options. Not automated.
- [ ] Log viewer: the output region can be focused and scrolled with arrow and Page keys. Not
      automated.
- [ ] No keyboard trap anywhere: Tab and Shift+Tab can always leave a widget.
  - [x] The palette is the only widget checked. Its trap is intended and Escape leaves it (see the
        command palette item above). Other widgets: not automated.
- [ ] Row-level actions (revoke, copy link, reset) are reachable without a mouse. Not automated.

## 2. Screen reader (NVDA with Firefox or Chrome on Windows, VoiceOver with Safari on macOS)

**NOT PERFORMED. Needs a human with NVDA or VoiceOver.** No browser test can judge spoken output,
focus order as heard, or live-region timing. The axe rules in section 5 only check markup.

- [ ] Headings: each page has one `h1`; sections are `h2`; the rendered outline makes sense.
- [ ] Landmarks: banner, main navigation ("Main"), main content; the side panel in Audit is
      announced as a complementary region named "Entry <id>".
- [ ] Tables (Inventory, Checks, Alerts, Audit, Account sessions and tokens, Chart data tables):
      headers are announced with each cell; captions or labels describe each table.
- [ ] Forms: each field's label is announced; the hint and error text are read after the label
      (`aria-describedby`); invalid fields announce "invalid" (`aria-invalid`).
- [ ] Status messages ("Saving…", "Loading…", chart loading, log stream status) are announced once
      and are not repeated while they change.
- [ ] Error messages (role="alert") are announced immediately after a failed submit.
- [ ] New token on Account: the "Copy this token now" message is announced; the token itself is
      read only when the screen reader user reaches it.
- [ ] Charts: the figure is announced with a summary of the range and the min/max/last values; the
      "Show data table" button works and the table is navigable.
- [ ] Status badges read as text (for example "Healthy" or "Down"), not as colour.
- [ ] Icon-only buttons have names: "Toggle sidebar", "Row density…", "Theme…", "Search".
- [ ] Setup wizard: step progress ("Step 2 of 4") and the current step title are announced on change.
- [ ] Sign-in with two-factor: the code field is announced as "Code" with one-time-code behaviour.

## 3. Forms and authentication (WCAG 2.2 3.3.x)

- [ ] Password fields accept paste and work with a password manager (Bitwarden, 1Password, the
      browser's own manager). Tested: sign-in, setup, Account password change, Users reset. Not
      automated: the browser suite fills fields with script, which is not a password manager.
- [ ] The TOTP code field accepts paste of a 6-digit code and offers the device's one-time code
      suggestion (iOS and Android keyboards, Chrome autofill). Not automated.
- [ ] No puzzle, memory or transcription test is required to sign in or to set up two-factor.
      Not automated.
- [ ] Redundant entry: data the user already gave (email, name) is not requested again in setup.
      Not automated.
- [ ] Each error explains what went wrong and how to fix it; no error relies on colour. Not
      automated. The sign-in error text is checked for "incorrect" only (`auth.spec.ts`).

## 4. Visual

- [x] Text reflows at 320 px width with no horizontal page scroll (tables scroll inside their box).
      Spec: `layout.spec.ts`, "no horizontal page scroll at 320 CSS px", over the ten signed-in
      routes listed in that file. The top bar wraps below 40rem and hides the spacer and the Ctrl K
      hint; the main gutter drops to 12 px; bare tables sit in `.table-wrap`; the select field is
      capped to its column. Every control stays visible and named.
- [ ] 200% browser zoom keeps all content and controls usable.
  - [x] Viewport 640 CSS px (equal to 200% zoom on a 1280 px display): the title, the sidebar
        toggle and Search stay inside the viewport on `/inventory`. Spec: `layout.spec.ts`, "at 200%
        zoom the primary controls stay on screen". Other pages are not covered by that check.
  - [x] Page width at 640 CSS px: no horizontal page scroll on the same routes. Spec:
        `layout.spec.ts`, "no horizontal page scroll at 640 CSS px". The cause on `/audit` was an
        absolutely positioned visually hidden cell label whose containing block was outside the table
        box; `.table-wrap` now sets `position: relative` in `src/lib/ui/global.css`.
- [ ] Turn on the OS "reduce motion" setting: the sidebar does not animate; no other motion remains.
  - [x] With `prefers-reduced-motion: reduce`, the sidebar's computed `transition-duration` is `0s`,
        and it is not `0s` without the preference. Spec: `layout.spec.ts`, "the sidebar does not
        animate when reduced motion is requested". Other motion: not automated.
- [ ] Light and dark themes both pass the contrast the automated tests compute; spot check the
      status badges and chart colours on screen.
  - [x] axe's `color-contrast` rule, run on rendered pixels, reports no violation on Overview,
        Checks, Alerts, Audit, Users, Settings, Account, Add a host, and a host item page (overview and
        logs tab), in both themes. Spec: `a11y.spec.ts`. Status badges and chart colours on
        sunken surfaces: not covered, and a human still spot checks them.
- [ ] Targets: icon buttons and links are at least 24 by 24 px. Compact density keeps 32 px rows.
  - [x] Top bar and sidebar targets are at least 24 by 24 CSS px. The user name link `a.user` is
        now `inline-flex` with `min-height: var(--target-size)`. Spec: `layout.spec.ts`, "icon
        buttons and links in the top bar and sidebar are at least 24 by 24 px". Compact density: not
        automated, and the main-content targets are not covered by that check.

## 5. Known gaps

- Screen-reader output, focus order as heard, and live-region timing are only checked by a human.
- jsdom does not compute colour contrast on rendered elements. The browser suite does, for the
  pages listed in section 4, but not for every combination a page can produce (for example a
  status badge on a sunken surface).
- The Audit detail panel is a non-modal side panel, so Tab can leave it. This is deliberate: it is
  announced as a region, not a dialog.
- The browser suite runs in Chromium only. Firefox and WebKit are not covered.
- Log viewer checks need a host whose journal logs; `logs.spec.ts` uses `E2E_LOG_UNIT` (default
  `systemd-journald.service`) and skips with a reason when the unit produces too few lines.

## 6. Defects found by the browser suite (fixed in this pass)

The browser checks failed on these before the fixes in this pass. Each now passes; the spec in
brackets proves it.

1. Skip link did not move focus into `<main>` (WCAG 2.4.1). `src/lib/ui/Shell.svelte`
   (`interceptLinks`). [`layout.spec.ts`]
2. Top bar wider than 320 CSS px (WCAG 1.4.10). `src/lib/ui/TopBar.svelte`. [`layout.spec.ts`]
3. Audit page wider than 640 CSS px (WCAG 1.4.10). `src/lib/ui/global.css` (`.table-wrap`).
   [`layout.spec.ts`]
4. User name link 21 px tall (WCAG 2.5.8). `src/lib/ui/TopBar.svelte` (`a.user`). [`layout.spec.ts`]
5. Bare tables widened the page at 320 CSS px. `src/routes/Users.svelte`,
   `src/routes/RoleBindings.svelte`, `src/routes/Account.svelte` now wrap them in `.table-wrap`.
6. Filter select widened the page at 320 CSS px. `src/lib/ui/SelectField.svelte`. [`layout.spec.ts`]
