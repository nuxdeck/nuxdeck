-- Append-only, hash-chained audit log. hash = SHA-256(prev_hash || canonical JSON of the row without hash).
CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    actor_type   TEXT NOT NULL,
    actor_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    ip           TEXT NOT NULL,
    result       TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    details_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL UNIQUE
);

-- No UPDATE or DELETE statement exists in the code; these triggers make the database refuse them too.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
