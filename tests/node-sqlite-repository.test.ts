import { readFileSync } from 'node:fs'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { D1RevealProofRepository } from '../src/adapters/d1-reveal-proof-repository'
import { D1SecretRepository } from '../src/adapters/d1-secret-repository'
import { NodeSqliteDatabase } from '../src/adapters/node-sqlite-database'
import { generateSecretId, prepareSecretRecord } from '../src/core/secret'

const OWNER_KEY_HASH = 'a'.repeat(64)
const REPLAY_KEY = 'b'.repeat(64)
const VERIFICATION_ID = 'c'.repeat(32)
const MIGRATIONS = [
  '0001_secrets.sql',
  '0002_environment.sql',
  '0003_secret_replay_key.sql',
  '0004_reveal_proofs.sql',
  '0005_reveal_proof_verification.sql',
  '0006_expire_legacy_share_links.sql',
  '0007_owner_capability.sql',
]

const openDatabases: NodeSqliteDatabase[] = []

function database(): NodeSqliteDatabase {
  const db = new NodeSqliteDatabase(':memory:')
  for (const migration of MIGRATIONS) {
    db.exec(readFileSync(path.resolve('migrations', migration), 'utf8'))
  }
  openDatabases.push(db)
  return db
}

function record() {
  const prepared = prepareSecretRecord(generateSecretId(), new Uint8Array([7, 8, 9]), 100, 900)
  if (!prepared.ok) {
    throw new Error(`failed to prepare test secret: ${prepared.reason}`)
  }

  return prepared.record
}

describe('Node SQLite persistence', () => {
  afterEach(() => {
    for (const db of openDatabases.splice(0)) {
      db.close()
    }
  })

  it('runs the existing secret repository atomically on SQLite', async () => {
    const repository = new D1SecretRepository(database())
    const secret = record()

    await expect(repository.create(secret, REPLAY_KEY, OWNER_KEY_HASH)).resolves.toEqual({
      kind: 'created',
      id: secret.id,
    })

    const results = await Promise.all([
      repository.consume(secret.id, 500),
      repository.consume(secret.id, 500),
      repository.consume(secret.id, 500),
    ])

    expect(results.filter((result) => result.kind === 'revealed')).toHaveLength(1)
    expect(results.filter((result) => result.kind === 'unavailable')).toHaveLength(2)
    expect((await repository.getStatus(secret.id, OWNER_KEY_HASH, 500))?.state).toBe('CONSUMED')
  })

  it('keeps create replay and owner semantics unchanged', async () => {
    const repository = new D1SecretRepository(database())
    const original = record()
    const replay = record()

    await expect(repository.create(original, REPLAY_KEY, OWNER_KEY_HASH)).resolves.toEqual({
      kind: 'created',
      id: original.id,
    })
    await expect(repository.create(replay, REPLAY_KEY, OWNER_KEY_HASH)).resolves.toEqual({
      kind: 'replayed',
      id: original.id,
    })
    await expect(repository.getStatus(original.id, 'd'.repeat(64), 500)).resolves.toBeUndefined()
    await expect(repository.revoke(original.id, OWNER_KEY_HASH, 500)).resolves.toMatchObject({
      kind: 'revoked',
    })
  })

  it('runs the existing reveal-proof repository on the same SQLite database', async () => {
    const db = database()
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
  })
})
