---
title: Audit log
description: Search and export the audit log, the hash chain, and how to verify it.
weight: 120
---

Every state-changing action writes an audit entry in the same database transaction as the change. Some reads are audited as well, including log streams, notification tests and exports.

## Search

**Audit log** in the UI, or `GET /api/v1/audit` (admin). Filters:

- `actor`, `action` (prefix match), `target_type`, `target_id`
- `result` (`success` or `failure`)
- `q` (free text), `from` and `to` (RFC 3339)
- `limit` and `cursor`, as for other lists

Text filters are at most 256 characters. Details are masked on every read, so secret-looking values never appear.

## Export

`GET /api/v1/audit/export` (admin) streams the matching entries as newline-delimited JSON (`application/x-ndjson`). The export itself is recorded before the first byte is sent. The export is JSON only; convert it with `jq` if you need CSV.

## Hash chain

Each entry stores `prev_hash` and `hash`:

```text
hash = SHA-256(prev_hash || canonical JSON of the entry)
```

The canonical JSON holds the entry's ID, time, actor, action, target, IP, result and details, with keys sorted. Changing or removing an entry breaks the chain from that point.

## Verify

- **At startup,** nuxd verifies the whole chain and logs `audit chain verified` with the entry count. A broken chain logs `AUD-CHAIN-001` with the first broken entry. nuxd keeps running; investigate.
- **On demand:** `GET /api/v1/audit/verify` returns `{"ok": true, "entries": N}`. On failure it adds `broken_at`, `reason` and `code`.
- **Restores** verify the restored chain before replacing data (`BAK-AUDIT-001`).

There is no `nuxd audit` subcommand in v0.1.
