-- Every certificate issued to an agent, so revoking the agent can deny all of them, not just the current one.
CREATE TABLE agent_certs (
    serial    TEXT PRIMARY KEY,
    agent_id  TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    issued_at INTEGER NOT NULL,
    not_after INTEGER NOT NULL
) STRICT;

CREATE INDEX agent_certs_agent ON agent_certs (agent_id);

-- Certificates issued before this table existed lived 24 hours.
INSERT INTO agent_certs (serial, agent_id, issued_at, not_after)
SELECT cert_serial, id, enrolled_at, enrolled_at + 86400000 FROM agents;
