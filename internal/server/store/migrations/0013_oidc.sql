-- OIDC single sign-on (ACC-3). v0.1 supports one provider, so its row is fixed at id 1.
-- The client secret lives in secrets; this row keeps only its reference.
CREATE TABLE oidc_providers (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    issuer               TEXT NOT NULL,
    client_id            TEXT NOT NULL,
    client_secret_ref    TEXT NOT NULL REFERENCES secrets (id),
    scopes_json          TEXT NOT NULL,
    groups_claim         TEXT NOT NULL,
    allowed_domains_json TEXT NOT NULL DEFAULT '[]',
    auto_provision       INTEGER NOT NULL DEFAULT 0 CHECK (auto_provision IN (0, 1)),
    link_existing        INTEGER NOT NULL DEFAULT 0 CHECK (link_existing IN (0, 1)),
    updated_at           INTEGER NOT NULL
) STRICT;

-- A sign-in waiting for its callback. Only the SHA-256 of the state is stored, the row is
-- single-use, and it expires after a few minutes.
CREATE TABLE oidc_logins (
    state_hash    TEXT PRIMARY KEY,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    redirect_to   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX oidc_logins_expires ON oidc_logins (expires_at);

-- Groups from the latest sign-in. Role bindings with subject_type oidc_group match against them.
CREATE TABLE oidc_user_groups (
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_name TEXT NOT NULL,
    PRIMARY KEY (user_id, group_name)
) STRICT;

-- An identity belongs to one account only.
CREATE UNIQUE INDEX users_oidc_identity ON users (oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;
