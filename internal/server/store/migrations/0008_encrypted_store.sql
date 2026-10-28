-- Encrypted secrets (T7). Every row is sealed with its own data key, which is wrapped by the
-- master key; the id is bound into both seals, so rows cannot be swapped. wrapped_dek starts
-- with a version byte so the wrapping can change later without rewriting this table's shape.
CREATE TABLE secrets (
    id          TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;
