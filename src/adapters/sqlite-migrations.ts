import migration1 from '../../migrations/0001_secrets.sql?raw'
import migration2 from '../../migrations/0002_environment.sql?raw'
import migration3 from '../../migrations/0003_secret_replay_key.sql?raw'
import migration4 from '../../migrations/0004_reveal_proofs.sql?raw'
import migration5 from '../../migrations/0005_reveal_proof_verification.sql?raw'
import migration6 from '../../migrations/0006_expire_legacy_share_links.sql?raw'
import migration7 from '../../migrations/0007_owner_capability.sql?raw'

import type { NodeSqliteDatabase } from './node-sqlite-database'

const SQLITE_MIGRATIONS = [
  migration1,
  migration2,
  migration3,
  migration4,
  migration5,
  migration6,
  migration7,
] as const

export function applySqliteMigrations(database: NodeSqliteDatabase): void {
  database.applyMigrations(SQLITE_MIGRATIONS)
}
