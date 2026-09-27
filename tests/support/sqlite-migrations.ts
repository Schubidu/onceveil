import { readFileSync } from 'node:fs'
import path from 'node:path'

const MIGRATIONS = [
  '0001_secrets.sql',
  '0002_environment.sql',
  '0003_secret_replay_key.sql',
  '0004_reveal_proofs.sql',
  '0005_reveal_proof_verification.sql',
  '0006_expire_legacy_share_links.sql',
  '0007_owner_capability.sql',
]

export function applySqliteMigrations(database: { exec(sql: string): void }): void {
  for (const migration of MIGRATIONS) {
    database.exec(readFileSync(path.resolve('migrations', migration), 'utf8'))
  }
}
