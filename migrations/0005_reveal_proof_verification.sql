ALTER TABLE reveal_proofs ADD COLUMN verification_id TEXT;
ALTER TABLE reveal_proofs ADD COLUMN verified_at_ms INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS reveal_proofs_verification_id_idx
  ON reveal_proofs (verification_id)
  WHERE verification_id IS NOT NULL;
