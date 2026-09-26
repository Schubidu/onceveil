CREATE TABLE IF NOT EXISTS onceveil_environment (
  id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
  environment TEXT NOT NULL CHECK (environment IN ('production', 'preview'))
) STRICT;
