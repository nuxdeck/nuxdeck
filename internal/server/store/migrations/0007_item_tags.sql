-- Tags and owners of hosts and containers (INV-3, INV-4). hosts.owner already exists from 0006.
CREATE TABLE item_tags (
    item_type TEXT NOT NULL CHECK (item_type IN ('host', 'container')),
    item_id   TEXT NOT NULL,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (item_type, item_id, key)
) STRICT;

CREATE INDEX item_tags_key_value ON item_tags (key, value);

ALTER TABLE containers ADD COLUMN owner TEXT NOT NULL DEFAULT '';
