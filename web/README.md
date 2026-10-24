# web

The Nux Deck UI: Svelte 5, TypeScript and Vite, built to static files and embedded into `nuxd` with Go's `embed` (`web/embed.go`). Licence: AGPL-3.0.

| Command                           | Does                                                        |
| --------------------------------- | ----------------------------------------------------------- |
| `make dev`                        | `nuxd` plus the Vite dev server with hot reload (port 5173) |
| `make web`                        | Production build into `dist/`, then the CSP check           |
| `npm run lint` / `check` / `test` | ESLint and Prettier, `svelte-check`, Vitest (including axe) |

Rules enforced by tests and lint, from `docs/08-engineering-spec.md` and `docs/06-ux.md`:

- Colours, spacing and type sizes come only from `src/lib/ui/tokens.css`; contrast is checked there for both themes.
- No `{@html}`, no inline `style=` attributes, no other origins, no hand-written calls to `/api` (the client will be generated).
- `scripts/check-csp.mjs` fails the build if `dist/index.html` needs inline script or style.

`dist/` holds only a `.gitkeep` placeholder in git, so the Go build works without Node. Icons are Lucide (ISC) and Feather (MIT) geometry in `src/lib/ui/icons.ts`.
