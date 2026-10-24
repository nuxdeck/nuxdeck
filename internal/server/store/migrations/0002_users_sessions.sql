-- Local accounts, role bindings and browser sessions (docs/08-engineering-spec.md, Data model).
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
    name            TEXT NOT NULL,
    password_hash   TEXT,
    totp_secret_ref TEXT,
    oidc_issuer     TEXT,
    oidc_subject    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE role_bindings (
    id           TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'oidc_group')),
    subject      TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    scope_json   TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX role_bindings_subject ON role_bindings (subject_type, subject);

-- The session cookie is never stored, only its SHA-256 as id_hash.
CREATE TABLE sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    ip           TEXT NOT NULL,
    user_agent   TEXT NOT NULL
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);
