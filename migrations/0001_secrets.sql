CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('AVAILABLE', 'CONSUMED', 'EXPIRED', 'REVOKED')),
  consumed_at_ms INTEGER,
  revoked_at_ms INTEGER,
  consume_token TEXT,
  CHECK (length(id) = 32),
  CHECK (expires_at_ms > created_at_ms)
) STRICT;

CREATE INDEX IF NOT EXISTS secrets_expiry_idx
  ON secrets (state, expires_at_ms);
