<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Accessibility manual checklist (NUX-48)

Automated checks run in `npx vitest run`: axe on every route and key state
(`src/a11y.routes.test.ts`, `src/a11y.states.test.ts`, `src/a11y.test.ts`), token contrast in both
themes and motion tokens (`src/lib/ui/tokens.test.ts`). jsdom does not lay out pages, so those
checks cannot see focus rings on real pixels, reflow, zoom, or what a screen reader says.

**Screen-reader testing has NOT been performed.** Nothing below has been run with NVDA, JAWS or
VoiceOver. Every item in section 2 is still open until a person has checked it.

## 1. Keyboard (any browser, no mouse)

Run on Chrome or Firefox at 100% and 200% zoom, and at 320 px width.

- [ ] Tab from the address bar reaches "Skip to main content" first; Enter moves focus into `<main>`.
- [ ] Every sidebar link, the search button, the user menu, density and theme toggles, and every
      button on each page can be reached and activated with Enter or Space.
- [ ] The focus ring is visible on every control in light and dark themes (2px `--color-focus`).
- [ ] The focus ring is not hidden under the sticky top bar or the side panels when tabbing.
- [ ] Tab order follows the visual order on Account, Audit, Settings, Users, Status pages editor,
      Alerts (all five views), Checks editor, and every setup wizard step.
- [ ] Route change (sidebar link, back button) moves focus to the page `<h1>`.
- [ ] Command palette (Ctrl/Cmd+K): opens with focus in the search box; arrow keys move through
      results; Enter runs one; Tab stays inside the palette; Escape closes it and focus returns to the
      button that opened it.
- [ ] Audit detail panel: "Details" opens it and focus moves to its Close button; Escape closes it
      and focus returns to the "Details" button that opened it.
- [ ] Tabs (Alerts views): arrow keys move between tabs; Tab leaves the tab list.
- [ ] Time-range picker: arrow keys move between options.
- [ ] Log viewer: the output region can be focused and scrolled with arrow and Page keys.
- [ ] No keyboard trap anywhere: Tab and Shift+Tab can always leave a widget.
- [ ] Row-level actions (revoke, copy link, reset) are reachable without a mouse.

## 2. Screen reader (NVDA with Firefox or Chrome on Windows, VoiceOver with Safari on macOS)

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
      browser's own manager). Tested: sign-in, setup, Account password change, Users reset.
- [ ] The TOTP code field accepts paste of a 6-digit code and offers the device's one-time code
      suggestion (iOS and Android keyboards, Chrome autofill).
- [ ] No puzzle, memory or transcription test is required to sign in or to set up two-factor.
- [ ] Redundant entry: data the user already gave (email, name) is not requested again in setup.
- [ ] Each error explains what went wrong and how to fix it; no error relies on colour.

## 4. Visual

- [ ] Text reflows at 320 px width with no horizontal page scroll (tables scroll inside their box).
- [ ] 200% browser zoom keeps all content and controls usable.
- [ ] Turn on the OS "reduce motion" setting: the sidebar does not animate; no other motion remains.
- [ ] Light and dark themes both pass the contrast the automated tests compute; spot check the
      status badges and chart colours on screen.
- [ ] Targets: icon buttons and links are at least 24 by 24 px. Compact density keeps 32 px rows.

## 5. Known gaps

- Screen-reader output, focus order as heard, and live-region timing are only checked by a human.
- jsdom does not compute colour contrast on rendered elements; `tokens.test.ts` checks the token
  pairs, not every combination a page can produce (for example a status badge on a sunken surface).
- The Audit detail panel is a non-modal side panel, so Tab can leave it. This is deliberate: it is
  announced as a region, not a dialog.
