-- UI-editable settings (docs/08-engineering-spec.md, Data model).
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_by TEXT,
    updated_at INTEGER NOT NULL
) STRICT;
