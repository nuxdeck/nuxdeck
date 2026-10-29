---
title: Hosts, containers, tags and owners
description: Browse inventory, search it, and label items with tags, environments and owners.
weight: 30
---

## Inventory

**Inventory** lists every enrolled host and the containers it runs. Each host shows its OS, distro, kernel, architecture, CPU count and memory, plus its status (online or offline). A host is marked gone when its agent is removed; gone items are hidden unless you ask for them (`--include-gone` in the CLI).

Containers show their runtime (Docker or Podman), image, state, ports and restart count. Labels are already redacted by nux-sockguard before they reach the server.

Inventory updates live in the browser over Server-Sent Events, so you do not need to reload.

## Search

The command palette and `GET /api/v1/search?q=` find hosts, containers and checks by name, ID and tag.

## Tags

Tags are `key:value` pairs on hosts, containers and checks. Enrolment tokens can add labels that become host tags.

The tag `env` is special: its value is the environment (for example `production` or `staging`). Role scopes match environments through this tag (see [Users and security](users-security.md)).

Filter lists with a tag: `nux hosts ls --tag env:production`, or `?tag=env:production` on the API.

## Owners

An owner is a free-text value that says who looks after an item. It appears in notifications and filters.

Changing tags or owners needs the operator role. The change is audited, and it uses ETag and `If-Match`, so a stale edit gets `API-PRE-001` instead of overwriting someone else's change.

## Lists

Lists are paginated (`limit` default 50, maximum 500; `cursor` from the previous page's `next_cursor`).
