import { describe, expect, it } from 'vitest'

import {
  consumeSecret,
  effectiveState,
  generateSecretId,
  prepareSecretRecord,
  revokeSecret,
  toSecretStatus,
  type ConsumeResult,
  type CreateResult,
  type PreparedSecretRecord,
  type RevokeResult,
  type SecretId,
  type SecretRecord,
  type SecretRepository,
} from '../src/core/secret'
import { secretRepositoryContract } from './support/secret-repository-contract'

const OWNER_KEY_HASH = 'a'.repeat(64)

class AsyncAtomicInMemorySecretRepository implements SecretRepository {
  private readonly records = new Map<SecretId, SecretRecord>()
  private readonly owners = new Map<SecretId, string>()
  private readonly replays = new Map<
    string,
    { id: SecretId; ttlMs: number; ownerKeyHash: string }
  >()
  private readonly queues = new Map<string, Promise<void>>()

  async create(
    record: PreparedSecretRecord,
    replayKey: string,
    ownerKeyHash: string,
  ): Promise<CreateResult> {
    return this.withLock(`create:${replayKey}`, async () => {
      await Promise.resolve()

      const replay = this.replays.get(replayKey)
      if (replay) {
        const ttlMs = record.expiresAtMs - record.createdAtMs
        if (
          !Number.isSafeInteger(ttlMs) ||
          replay.ttlMs !== ttlMs ||
          replay.ownerKeyHash !== ownerKeyHash
        ) {
          return { kind: 'replay_conflict' }
        }

        return { kind: 'replayed', id: replay.id }
      }

      if (this.records.has(record.id)) {
        return { kind: 'duplicate_id' }
      }

      this.records.set(record.id, record)
      this.owners.set(record.id, ownerKeyHash)
      this.replays.set(replayKey, {
        id: record.id,
        ttlMs: record.expiresAtMs - record.createdAtMs,
        ownerKeyHash,
      })
      return { kind: 'created', id: record.id }
    })
  }

  async consume(id: SecretId, nowMs: number): Promise<ConsumeResult | { kind: 'not_found' }> {
    const result = await this.mutate(id, async (record) => {
      await Promise.resolve()
      const decision = consumeSecret(record, nowMs)
      return {
        nextState: decision.nextState,
        result: decision.result,
      }
    })

    return result ?? { kind: 'not_found' }
  }

  async revoke(
    id: SecretId,
    ownerKeyHash: string,
    nowMs: number,
  ): Promise<RevokeResult | { kind: 'not_found' }> {
    if (this.owners.get(id) !== ownerKeyHash) {
      return { kind: 'not_found' }
    }

    const result = await this.mutate(id, async (record) => {
      await Promise.resolve()
      const decision = revokeSecret(record, nowMs)
      return {
        nextState: decision.nextState,
        result: decision.result,
      }
    })

    return result ?? { kind: 'not_found' }
  }

  async getStatus(id: SecretId, ownerKeyHash: string, nowMs: number) {
    if (this.owners.get(id) !== ownerKeyHash) {
      return undefined
    }

    return this.mutate(id, async (record) => {
      await Promise.resolve()
      const nextState = effectiveState(record, nowMs)
      return {
        nextState,
        result: toSecretStatus({ ...record, state: nextState }),
      }
    })
  }

  private async mutate<Result>(
    id: SecretId,
    mutation: (
      record: SecretRecord,
    ) => Promise<{ nextState: SecretRecord['state']; result: Result }>,
  ): Promise<Result | undefined> {
    return this.withLock(id, async () => {
      const record = this.records.get(id)
      if (!record) {
        return undefined
      }

      const outcome = await mutation(record)
      this.records.set(id, { ...record, state: outcome.nextState })
      return outcome.result
    })
  }

  private async withLock<Result>(id: string, operation: () => Promise<Result>): Promise<Result> {
    const previous = this.queues.get(id) ?? Promise.resolve()
    let release: (() => void) | undefined
    const current = new Promise<void>((resolve) => {
      release = resolve
    })
    this.queues.set(
      id,
      previous.then(() => current),
    )

    await previous

    try {
      return await operation()
    } finally {
      release?.()
    }
  }
}

function record(): PreparedSecretRecord {
  const prepared = prepareSecretRecord(generateSecretId(), new Uint8Array([7, 8, 9]), 100, 900)

  if (!prepared.ok) {
    throw new Error(`failed to prepare test secret: ${prepared.reason}`)
  }

  return prepared.record
}

secretRepositoryContract('in-memory reference', () => ({
  repository: new AsyncAtomicInMemorySecretRepository(),
}))

describe('SecretRepository fail-closed malformed-state behavior', () => {
  it('fails closed when persisted temporal data is malformed', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const malformed = {
      ...secret,
      expiresAtMs: Number.NaN,
    } as PreparedSecretRecord

    expect(await repository.create(malformed, 'replay-malformed', OWNER_KEY_HASH)).toEqual({
      kind: 'created',
      id: malformed.id,
    })
    expect(await repository.consume(secret.id, 500)).toEqual({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
    expect((await repository.getStatus(secret.id, OWNER_KEY_HASH, 500))?.state).toBe('EXPIRED')
  })

  it('fails closed for an unknown persisted lifecycle state', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const malformed = {
      ...secret,
      state: 'UNKNOWN',
    } as unknown as PreparedSecretRecord

    expect(await repository.create(malformed, 'replay-malformed', OWNER_KEY_HASH)).toEqual({
      kind: 'created',
      id: malformed.id,
    })
    expect(await repository.consume(secret.id, 500)).toEqual({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
    expect((await repository.getStatus(secret.id, OWNER_KEY_HASH, 500))?.state).toBe('EXPIRED')
  })
})
