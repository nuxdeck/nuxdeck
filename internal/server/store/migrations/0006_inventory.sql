-- Hosts and containers reported by agents (docs/08-engineering-spec.md, Data model).
CREATE TABLE hosts (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL UNIQUE REFERENCES agents (id),
    hostname      TEXT NOT NULL,
    os            TEXT NOT NULL,
    distro        TEXT NOT NULL,
    kernel        TEXT NOT NULL,
    arch          TEXT NOT NULL,
    cpu_count     INTEGER NOT NULL,
    memory_bytes  INTEGER NOT NULL,
    facts_json    TEXT NOT NULL DEFAULT '{}',
    owner         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL CHECK (status IN ('online', 'offline', 'gone')),
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    gone_at       INTEGER
) STRICT;

CREATE TABLE containers (
    id            TEXT PRIMARY KEY,
    host_id       TEXT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    runtime       TEXT NOT NULL CHECK (runtime IN ('docker', 'podman')),
    runtime_id    TEXT NOT NULL,
    name          TEXT NOT NULL,
    image         TEXT NOT NULL,
    state         TEXT NOT NULL,
    ports_json    TEXT NOT NULL DEFAULT '[]',
    labels_json   TEXT NOT NULL DEFAULT '{}',
    restart_count INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER,
    gone_at       INTEGER,
    UNIQUE (host_id, runtime_id)
) STRICT;

CREATE INDEX containers_host ON containers (host_id);

-- Expand step: agents point at their host (the spec's agents.host_id); set when the first snapshot arrives.
ALTER TABLE agents ADD COLUMN host_id TEXT REFERENCES hosts (id);
