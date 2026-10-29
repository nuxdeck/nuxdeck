-- Alerting (ALR-1..ALR-5, NUX-30..NUX-32, docs/08-engineering-spec.md, Data model).
-- Times are Unix milliseconds. selector_json and params_json hold public configuration only;
-- channel credentials live in secrets and are referenced by secret_refs_json (field -> secret id).
CREATE TABLE alert_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('check_down', 'host_offline', 'container_stopped', 'metric_threshold', 'tls_expiring')),
    params_json TEXT NOT NULL,
    selector_json TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    rev         INTEGER NOT NULL DEFAULT 1,
    created_by  TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

-- Rule name, kind and severity are copied so an alert stays readable after its rule is edited or deleted.
CREATE TABLE alerts (
    id               TEXT PRIMARY KEY,
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    kind             TEXT NOT NULL,
    severity         TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    item_type        TEXT NOT NULL CHECK (item_type IN ('host', 'container', 'check')),
    item_id          TEXT NOT NULL,
    item_name        TEXT NOT NULL,
    summary          TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('open', 'acked', 'resolved')),
    opened_at        INTEGER NOT NULL,
    acked_by         TEXT NOT NULL DEFAULT '',
    acked_at         INTEGER,
    resolved_at      INTEGER,
    resolve_reason   TEXT NOT NULL DEFAULT '',
    flap_count       INTEGER NOT NULL DEFAULT 0,
    last_notified_at INTEGER,
    notify_pending   INTEGER NOT NULL DEFAULT 0 CHECK (notify_pending IN (0, 1))
) STRICT;

-- One open (or acknowledged) alert per fingerprint, enforced by the database.
CREATE UNIQUE INDEX alerts_one_active ON alerts (fingerprint) WHERE state IN ('open', 'acked');
CREATE INDEX alerts_state ON alerts (state, id);
CREATE INDEX alerts_fingerprint_resolved ON alerts (fingerprint, resolved_at);

-- Silences and maintenance windows (kind). A silence mutes notifications; alerts still open and record.
CREATE TABLE silences (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('silence', 'maintenance')),
    selector_json TEXT NOT NULL,
    starts_at     INTEGER NOT NULL,
    ends_at       INTEGER NOT NULL,
    reason        TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    CHECK (ends_at > starts_at)
) STRICT;

CREATE INDEX silences_ends ON silences (ends_at);

CREATE TABLE channels (
    id               TEXT PRIMARY KEY,
    type             TEXT NOT NULL CHECK (type IN ('smtp', 'slack', 'teams', 'discord', 'telegram', 'webhook')),
    name             TEXT NOT NULL UNIQUE,
    config_json      TEXT NOT NULL,
    secret_refs_json TEXT NOT NULL DEFAULT '{}',
    enabled          INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    allow_private    INTEGER NOT NULL DEFAULT 0 CHECK (allow_private IN (0, 1)),
    rev              INTEGER NOT NULL DEFAULT 1,
    last_status      TEXT NOT NULL DEFAULT 'never' CHECK (last_status IN ('never', 'ok', 'failed')),
    last_error_code  TEXT NOT NULL DEFAULT '',
    last_sent_at     INTEGER,
    created_by       TEXT NOT NULL,
    updated_by       TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
) STRICT;

-- Ordered notification routes; the whole list is replaced in one transaction.
CREATE TABLE routes (
    id            TEXT PRIMARY KEY,
    position      INTEGER NOT NULL UNIQUE,
    selector_json TEXT NOT NULL,
    channel_id    TEXT NOT NULL REFERENCES channels (id) ON DELETE CASCADE,
    continue      INTEGER NOT NULL CHECK (continue IN (0, 1))
) STRICT;

-- Small key/value state of the alerting module: routes_rev (ETag of the route list) and
-- defaults_seeded (the default rules were created once and are never recreated).
CREATE TABLE alerting_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT, WITHOUT ROWID;
