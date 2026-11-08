-- Opt-in telemetry state (ADR-007, docs/08-engineering-spec.md, Data model). One row; the install ID
-- exists only while telemetry is on.
CREATE TABLE telemetry_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    install_id   TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    last_sent_at INTEGER
) STRICT;

INSERT INTO telemetry_state (id) VALUES (1);
