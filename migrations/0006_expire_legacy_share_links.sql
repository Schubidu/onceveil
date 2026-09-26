CREATE TRIGGER IF NOT EXISTS secrets_require_replay_key
BEFORE INSERT ON secrets
WHEN NEW.replay_key IS NULL
BEGIN
  SELECT RAISE(ABORT, 'replay_key_required');
END;

UPDATE secrets
SET state = 'EXPIRED'
WHERE state = 'AVAILABLE'
  AND replay_key IS NULL;
