UPDATE secrets
SET state = 'EXPIRED'
WHERE state = 'AVAILABLE'
  AND replay_key IS NULL;
