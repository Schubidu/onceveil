CREATE TABLE mcp_handoffs (
  flow_id TEXT PRIMARY KEY NOT NULL
    CHECK (length(flow_id) = 32 AND flow_id NOT GLOB '*[^0-9a-f]*'),
  action TEXT NOT NULL CHECK (action IN ('create', 'reveal')),
  state TEXT NOT NULL CHECK (state IN ('PENDING', 'COMPLETED')),
  handoff_token_hash TEXT NOT NULL
    CHECK (length(handoff_token_hash) = 64 AND handoff_token_hash NOT GLOB '*[^0-9a-f]*'),
  handoff_token_nonce TEXT NOT NULL,
  handoff_token_ciphertext TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  handoff_expires_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  secret_id TEXT,
  owner_key_hash TEXT,
  CHECK (handoff_expires_at_ms > created_at_ms),
  CHECK (
    (state = 'PENDING' AND completed_at_ms IS NULL) OR
    (state = 'COMPLETED' AND completed_at_ms IS NOT NULL)
  ),
  CHECK (
    action = 'reveal' OR
    state = 'PENDING' OR
    (
      secret_id IS NOT NULL AND
      length(secret_id) = 32 AND
      secret_id NOT GLOB '*[^0-9a-f]*' AND
      owner_key_hash IS NOT NULL AND
      length(owner_key_hash) = 64 AND
      owner_key_hash NOT GLOB '*[^0-9a-f]*'
    )
  )
) STRICT;

CREATE INDEX mcp_handoffs_secret_id_idx
  ON mcp_handoffs(secret_id)
  WHERE secret_id IS NOT NULL;
