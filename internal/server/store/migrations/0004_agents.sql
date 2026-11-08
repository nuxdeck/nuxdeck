-- Agent enrolment (docs/08-engineering-spec.md, Data model). Only the SHA-256 of a token is stored.
CREATE TABLE enrollment_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users (id),
    labels_json TEXT NOT NULL DEFAULT '{}',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
) STRICT;

-- host_id and capabilities_json arrive with the inventory module (expand, then migrate).
CREATE TABLE agents (
    id          TEXT PRIMARY KEY,
    token_id    TEXT NOT NULL UNIQUE REFERENCES enrollment_tokens (id),
    cert_serial TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL,
    arch        TEXT NOT NULL,
    version     TEXT NOT NULL,
    labels_json TEXT NOT NULL DEFAULT '{}',
    enrolled_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    revoked_at  INTEGER
) STRICT;

CREATE INDEX agents_cert_serial ON agents (cert_serial);
