import { describe, expect, it } from 'vitest'

import { D1RevealProofRepository } from '../src/adapters/d1-reveal-proof-repository'
import { D1SecretRepository } from '../src/adapters/d1-secret-repository'
import { NodeSqliteDatabase } from '../src/adapters/node-sqlite-database'
import { generateSecretId, prepareSecretRecord } from '../src/core/secret'
import { secretRepositoryContract } from './support/secret-repository-contract'
import { applySqliteMigrations } from './support/sqlite-migrations'

const OWNER_KEY_HASH = 'a'.repeat(64)
const REPLAY_KEY = 'b'.repeat(64)
const VERIFICATION_ID = 'c'.repeat(32)

function database(): NodeSqliteDatabase {
  const db = new NodeSqliteDatabase(':memory:')
  applySqliteMigrations(db)
  return db
}

function record() {
  const prepared = prepareSecretRecord(generateSecretId(), new Uint8Array([7, 8, 9]), 100, 900)
  if (!prepared.ok) {
    throw new Error(`failed to prepare test secret: ${prepared.reason}`)
  }

  return prepared.record
}

secretRepositoryContract('Node SQLite', () => {
  const db = database()
  return {
    repository: new D1SecretRepository(db),
    close: () => db.close(),
  }
})

describe('Node SQLite reveal-proof persistence', () => {
  it('runs the existing reveal-proof repository on the same SQLite database', async () => {
    const db = database()

    try {
      const secrets = new D1SecretRepository(db)
      const proofs = new D1RevealProofRepository(db)
      const secret = record()

      await secrets.create(secret, REPLAY_KEY, OWNER_KEY_HASH)

      const proof = await proofs.prepare(secret.id, REPLAY_KEY, VERIFICATION_ID, 200)
      expect(proof?.verificationId).toBe(VERIFICATION_ID)
      expect(await proofs.verify(secret.id, VERIFICATION_ID, 300)).toBe(true)

      if (!proof) {
        throw new Error('proof was not prepared')
      }

      expect(await proofs.consume(secret.id, proof.value, 400)).toBe(true)
      expect(await proofs.consume(secret.id, proof.value, 400)).toBe(false)
    } finally {
      db.close()
    }
  })
})
