-- Public status pages (STP-1..STP-3, docs/08-engineering-spec.md, Data model).
-- The public surface never reads these tables directly: it serves a projection built from them.
CREATE TABLE status_pages (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    published   INTEGER NOT NULL CHECK (published IN (0, 1)),
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    rev         INTEGER NOT NULL DEFAULT 1
) STRICT;

-- check_ids_json is a JSON array of check IDs; a deleted check simply stops counting.
CREATE TABLE status_components (
    id             TEXT PRIMARY KEY,
    page_id        TEXT NOT NULL REFERENCES status_pages (id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    position       INTEGER NOT NULL,
    check_ids_json TEXT NOT NULL
) STRICT;

CREATE INDEX status_components_page ON status_components (page_id, position);

CREATE TABLE incidents (
    id          TEXT PRIMARY KEY,
    page_id     TEXT NOT NULL REFERENCES status_pages (id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
    impact      TEXT NOT NULL CHECK (impact IN ('none', 'minor', 'major')),
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    resolved_at INTEGER
) STRICT;

CREATE INDEX incidents_page ON incidents (page_id, created_at);

-- Append-only timeline of an incident.
CREATE TABLE incident_updates (
    id          INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
    body        TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX incident_updates_incident ON incident_updates (incident_id, id);
