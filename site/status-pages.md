---
title: Status pages
description: Publish a public status page for checks, with components and incidents.
weight: 70
---

A status page is a public, read-only view of selected checks, served without signing in.

## Create a page

In **Status pages**, create a page with a title, an optional description and a **slug**. Components group checks; each component lists the checks it reflects (up to 50 per component, 20 components per page).

- The slug is 1 to 64 characters: lowercase letters, digits and interior hyphens. `assets` is reserved. A slug cannot be changed after creation and must be unique (`STP-SLUG-001`).
- Set `published` to true to make the page visible. Unpublished pages are not served.
- A server holds up to 100 pages.

The public address is `https://<host>:8443/status/<slug>`. Unknown, unpublished and malformed slugs return the same not-found response, so the page does not reveal which slugs exist.

## Incidents

Create an incident with a title (up to 140 characters) and a body (up to 2000). Post updates to it, then resolve it. Each page keeps up to 500 incidents, and each incident up to 100 updates. Incidents are shown on the public page.

API: `GET|POST /api/v1/status-pages`, `GET|PUT|DELETE /api/v1/status-pages/{id}`, `GET|POST /api/v1/status-pages/{id}/incidents`, `POST .../incidents/{incidentId}/updates`, `POST .../incidents/{incidentId}/resolve`, `DELETE .../incidents/{incidentId}`. Writes need the operator role.

## Rate limit

The public route allows 120 requests per client address per minute. Every request counts, including misses. Above that limit the server answers with `Retry-After: 60` and `STP-RATE-001`.
