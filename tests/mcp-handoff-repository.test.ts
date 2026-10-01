import { describe, expect, it } from 'vitest'

import { D1McpHandoffRepository } from '../src/adapters/d1-mcp-handoff-repository'
import { D1SecretRepository } from '../src/adapters/d1-secret-repository'
import { NodeSqliteDatabase } from '../src/adapters/node-sqlite-database'
import { applySqliteMigrations } from '../src/adapters/sqlite-migrations'
import { revealAuthorizationFromFragment } from '../src/browser/secret-crypto'
import { encryptedShareForCreate } from '../src/browser/secret-create-retry'
import type { McpFlowId, McpHandoffRecord, SealedMcpValue } from '../src/core/mcp-handoff'
import type { OwnerCapabilityHash } from '../src/core/owner-capability'
import type { SecretId } from '../src/core/secret'
import { createSecretResponse } from '../src/runtime/secret-http'

const TOKEN_HASH = 'a'.repeat(64)
const OWNER_HASH = 'b'.repeat(64) as OwnerCapabilityHash
const SECRET_ID = 'c'.repeat(32) as SecretId
const SEALED_TOKEN: SealedMcpValue = {
  nonce: 'nonce',
  ciphertext: 'ciphertext',
}

function database(): NodeSqliteDatabase {
  const db = new NodeSqliteDatabase(':memory:')
  applySqliteMigrations(db)
  return db
}

async function createAvailableSecret(
  db: NodeSqliteDatabase,
  id: SecretId = SECRET_ID,
  nowMs = 1_000,
) {
  const encrypted = await encryptedShareForCreate('repository reveal target', undefined)
  const response = await createSecretResponse(
    new Request('https://onceveil.test/api/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload: encrypted.encrypted.payload,
        ownerKeyHash: encrypted.ownerCapabilityHash,
      }),
    }),
    new D1SecretRepository(db),
    nowMs,
    () => id,
  )
  expect(response.status).toBe(201)

  return {
    revealAuthorization: revealAuthorizationFromFragment(encrypted.encrypted.fragment),
    ownerKeyHash: encrypted.ownerCapabilityHash,
  }
}

function pending(flowId: string, action: 'create' | 'reveal'): McpHandoffRecord {
  return {
    flowId: flowId as McpFlowId,
    action,
    state: 'PENDING',
    handoffTokenHash: TOKEN_HASH,
    handoffToken: SEALED_TOKEN,
    createdAtMs: 1_000,
    handoffExpiresAtMs: 2_000,
  }
}

describe('MCP handoff repository', () => {
  it('authorizes only the matching live handoff token hash', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const record = pending('1'.repeat(32), 'reveal')
      await expect(repository.create(record)).resolves.toBe(true)

      await expect(
        repository.getAuthorized(record.flowId, TOKEN_HASH, 1_999),
      ).resolves.toMatchObject({
        flowId: record.flowId,
        action: 'reveal',
        state: 'PENDING',
      })
      await expect(
        repository.getAuthorized(record.flowId, '0'.repeat(64), 1_999),
      ).resolves.toBeUndefined()
      await expect(
        repository.getAuthorized(record.flowId, TOKEN_HASH, 2_000),
      ).resolves.toBeUndefined()
    } finally {
      db.close()
    }
  })

  it('cancels a pending handoff by deleting its transition state', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const pendingRecord = pending('4'.repeat(32), 'create')
      await expect(repository.create(pendingRecord)).resolves.toBe(true)

      await expect(repository.cancel(pendingRecord.flowId)).resolves.toBe(true)
      await expect(repository.get(pendingRecord.flowId)).resolves.toBeUndefined()
      await expect(repository.cancel(pendingRecord.flowId)).resolves.toBe(false)
    } finally {
      db.close()
    }
  })

  it('completes reveal once and treats an identical retry as replay', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const record = pending('2'.repeat(32), 'reveal')
      await repository.create(record)
      const target = await createAvailableSecret(db)

      await expect(
        repository.completeReveal(
          record.flowId,
          TOKEN_HASH,
          SECRET_ID,
          target.revealAuthorization,
          1_500,
        ),
      ).resolves.toBe('completed')
      await expect(
        repository.completeReveal(
          record.flowId,
          TOKEN_HASH,
          SECRET_ID,
          target.revealAuthorization,
          1_501,
        ),
      ).resolves.toBe('replayed')
      await expect(
        repository.completeReveal(
          record.flowId,
          TOKEN_HASH,
          'd'.repeat(32) as SecretId,
          target.revealAuthorization,
          1_502,
        ),
      ).resolves.toBe('unavailable')
      const completed = await repository.get(record.flowId)
      expect(completed).toMatchObject({
        state: 'COMPLETED',
        completedAtMs: 1_500,
        secretId: SECRET_ID,
      })
      expect(completed?.handoffToken).toBeUndefined()
    } finally {
      db.close()
    }
  })

  it('completes create without storing a raw owner capability', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const record = pending('3'.repeat(32), 'create')
      await repository.create(record)

      await expect(
        repository.completeCreate(record.flowId, TOKEN_HASH, SECRET_ID, OWNER_HASH, 1_500),
      ).resolves.toBe('completed')
      await expect(
        repository.completeCreate(record.flowId, TOKEN_HASH, SECRET_ID, OWNER_HASH, 1_501),
      ).resolves.toBe('replayed')
      await expect(
        repository.completeCreate(
          record.flowId,
          TOKEN_HASH,
          'd'.repeat(32) as SecretId,
          OWNER_HASH,
          1_502,
        ),
      ).resolves.toBe('unavailable')

      const row = db
        .prepare(
          'SELECT secret_id, owner_key_hash, handoff_token_ciphertext FROM mcp_handoffs WHERE flow_id = ?',
        )
        .bind(record.flowId)
      const stored = await row.first<Record<string, unknown>>()
      expect(stored).toEqual({
        secret_id: SECRET_ID,
        owner_key_hash: OWNER_HASH,
        handoff_token_ciphertext: '',
      })
    } finally {
      db.close()
    }
  })

  it('prunes expired transition rows but keeps completed create management mappings', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const expiredPendingCreate = pending('6'.repeat(32), 'create')
      const completedReveal = pending('7'.repeat(32), 'reveal')
      const completedCreate = pending('8'.repeat(32), 'create')

      await repository.create(expiredPendingCreate)
      await repository.create(completedReveal)
      await repository.create(completedCreate)
      const target = await createAvailableSecret(db)
      await repository.completeReveal(
        completedReveal.flowId,
        TOKEN_HASH,
        SECRET_ID,
        target.revealAuthorization,
        1_500,
      )
      await repository.completeCreate(
        completedCreate.flowId,
        TOKEN_HASH,
        SECRET_ID,
        OWNER_HASH,
        1_500,
      )

      const fresh: McpHandoffRecord = {
        ...pending('9'.repeat(32), 'reveal'),
        createdAtMs: 2_001,
        handoffExpiresAtMs: 3_001,
      }
      await expect(repository.create(fresh)).resolves.toBe(true)

      await expect(repository.get(expiredPendingCreate.flowId)).resolves.toBeUndefined()
      await expect(repository.get(completedReveal.flowId)).resolves.toBeUndefined()
      await expect(repository.get(completedCreate.flowId)).resolves.toMatchObject({
        state: 'COMPLETED',
        secretId: SECRET_ID,
        ownerKeyHash: OWNER_HASH,
        handoffTokenHash: '0'.repeat(64),
      })
      await expect(repository.get(fresh.flowId)).resolves.toMatchObject({
        state: 'PENDING',
      })
    } finally {
      db.close()
    }
  })

  it('atomically refuses reveal completion after the target leaves AVAILABLE', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const secrets = new D1SecretRepository(db)
      const record = pending('a'.repeat(32), 'reveal')
      await repository.create(record)
      const target = await createAvailableSecret(db)

      await expect(secrets.revoke(SECRET_ID, target.ownerKeyHash, 1_400)).resolves.toMatchObject({
        kind: 'revoked',
      })
      await expect(
        repository.completeReveal(
          record.flowId,
          TOKEN_HASH,
          SECRET_ID,
          target.revealAuthorization,
          1_500,
        ),
      ).resolves.toBe('unavailable')

      await expect(repository.get(record.flowId)).resolves.toMatchObject({
        state: 'PENDING',
      })
    } finally {
      db.close()
    }
  })

  it('indexes handoff expiry for bounded cleanup', async () => {
    const db = database()
    try {
      const index = await db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'mcp_handoffs_expiry_idx'",
        )
        .first<{ name: string }>()

      expect(index?.name).toBe('mcp_handoffs_expiry_idx')
    } finally {
      db.close()
    }
  })

  it('cannot complete an expired or wrongly authorized handoff', async () => {
    const db = database()
    try {
      const repository = new D1McpHandoffRepository(db)
      const reveal = pending('4'.repeat(32), 'reveal')
      const create = pending('5'.repeat(32), 'create')
      await repository.create(reveal)
      await repository.create(create)
      const target = await createAvailableSecret(db)

      await expect(
        repository.completeReveal(
          reveal.flowId,
          TOKEN_HASH,
          SECRET_ID,
          target.revealAuthorization,
          2_000,
        ),
      ).resolves.toBe('unavailable')
      await expect(
        repository.completeCreate(create.flowId, '0'.repeat(64), SECRET_ID, OWNER_HASH, 1_500),
      ).resolves.toBe('unavailable')
    } finally {
      db.close()
    }
  })
})
