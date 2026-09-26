ALTER TABLE secrets
  ADD COLUMN owner_key_hash TEXT
  CHECK (owner_key_hash IS NULL OR length(owner_key_hash) = 64);

CREATE TRIGGER IF NOT EXISTS secrets_require_owner_key_hash
BEFORE INSERT ON secrets
WHEN NEW.owner_key_hash IS NULL
BEGIN
  SELECT RAISE(ABORT, 'owner_key_hash_required');
END;
