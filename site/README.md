# Nux Deck user docs

This directory is the source of **docs.nuxdeck.com**.

## Convention

- One Markdown file per page, UTF-8, LF line endings.
- Each page starts with YAML front matter: `title` (required), `description` (one sentence), `weight` (sort order, lower first).
- Links are relative (`[Install](install.md)`), so the tree also reads correctly on GitHub.
- Commands are shown as they are typed. Every flag, key, endpoint and error code named here exists in the code; when you change one, change the page.
- No generator is required. Any static site generator that reads front matter (Hugo, MkDocs, Jekyll) can build this tree; the choice of generator is deliberately left open.

## Generated pages

`reference/error-codes.md` is generated from `internal/errcode/codes.go`. Do not edit it by hand.

```sh
go run ./site/tools/errorcodes          # regenerate
go run ./site/tools/errorcodes -check   # fail if stale (also run by go test)
go test ./site/tools/errorcodes/
```

The tool uses only the Go standard library and the repository's own `internal/errcode` package.
