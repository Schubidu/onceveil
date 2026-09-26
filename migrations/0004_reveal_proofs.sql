CREATE TABLE IF NOT EXISTS reveal_proofs (
  proof_hash TEXT PRIMARY KEY NOT NULL,
  secret_id TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  CHECK (length(proof_hash) = 64),
  CHECK (length(secret_id) = 32),
  CHECK (expires_at_ms > issued_at_ms)
) STRICT;

CREATE INDEX IF NOT EXISTS reveal_proofs_expiry_idx
  ON reveal_proofs (expires_at_ms, consumed_at_ms);
