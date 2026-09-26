ALTER TABLE secrets
  ADD COLUMN replay_key TEXT
  CHECK (replay_key IS NULL OR length(replay_key) = 64);

CREATE UNIQUE INDEX IF NOT EXISTS secrets_replay_key_idx
  ON secrets (replay_key)
  WHERE replay_key IS NOT NULL;
