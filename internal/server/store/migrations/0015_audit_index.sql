-- Search indexes for the audit log (AUD-3). Indexes only: the log is append-only and its rows are never touched.
CREATE INDEX audit_log_actor ON audit_log (actor_id, id);
CREATE INDEX audit_log_action ON audit_log (action, id);
CREATE INDEX audit_log_target ON audit_log (target_type, target_id, id);
CREATE INDEX audit_log_ts ON audit_log (ts);
