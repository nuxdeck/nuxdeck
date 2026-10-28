-- Uptime checks (UPT-1..UPT-3, UPT-5, docs/08-engineering-spec.md, Data model).
-- spec_json holds the public configuration only; credentials live in secrets and are referenced
-- by secret_refs_json (field name -> secret id).
CREATE TABLE checks (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL CHECK (type IN ('http', 'tcp', 'dns', 'tls', 'ping')),
    spec_json        TEXT NOT NULL,
    secret_refs_json TEXT NOT NULL DEFAULT '{}',
    runner           TEXT NOT NULL,
    interval_s       INTEGER NOT NULL CHECK (interval_s BETWEEN 20 AND 86400),
    timeout_s        INTEGER NOT NULL CHECK (timeout_s BETWEEN 1 AND 60),
    retries          INTEGER NOT NULL CHECK (retries BETWEEN 0 AND 5),
    enabled          INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    allow_private    INTEGER NOT NULL DEFAULT 0 CHECK (allow_private IN (0, 1)),
    rev              INTEGER NOT NULL DEFAULT 1,
    created_by       TEXT NOT NULL,
    updated_by       TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
) STRICT;

CREATE INDEX checks_runner ON checks (runner);

-- Current state of each check, so a restart does not forget what is up or down.
CREATE TABLE check_state (
    check_id         TEXT PRIMARY KEY REFERENCES checks (id) ON DELETE CASCADE,
    status           TEXT NOT NULL CHECK (status IN ('up', 'down', 'unknown')),
    since_at         INTEGER NOT NULL,
    last_checked_at  INTEGER NOT NULL,
    last_latency_ms  INTEGER NOT NULL,
    last_error_code  TEXT NOT NULL,
    last_detail      TEXT NOT NULL
) STRICT;

-- Pruned after 90 days; the daily rollups outlive them.
CREATE TABLE check_results (
    id         INTEGER PRIMARY KEY,
    check_id   TEXT NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
    ts         INTEGER NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('up', 'down', 'unknown')),
    latency_ms INTEGER NOT NULL,
    error_code TEXT NOT NULL,
    detail     TEXT NOT NULL
) STRICT;

CREATE INDEX check_results_check_ts ON check_results (check_id, ts);

-- One row per UTC day (day = unix seconds at 00:00 UTC). Seconds are results times the interval.
CREATE TABLE check_rollups_daily (
    check_id       TEXT NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
    day            INTEGER NOT NULL,
    up_s           INTEGER NOT NULL,
    down_s         INTEGER NOT NULL,
    avg_latency_ms INTEGER NOT NULL,
    PRIMARY KEY (check_id, day)
) STRICT, WITHOUT ROWID;
