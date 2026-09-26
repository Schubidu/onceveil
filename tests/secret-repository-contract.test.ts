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

class AsyncAtomicInMemorySecretRepository implements SecretRepository {
  private readonly records = new Map<SecretId, SecretRecord>()
  private readonly replays = new Map<string, { id: SecretId; ttlMs: number }>()
  private readonly queues = new Map<string, Promise<void>>()

  async create(record: PreparedSecretRecord, replayKey: string): Promise<CreateResult> {
    return this.withLock(`create:${replayKey}`, async () => {
      await Promise.resolve()

      const replay = this.replays.get(replayKey)
      if (replay) {
        const ttlMs = record.expiresAtMs - record.createdAtMs
        if (!Number.isSafeInteger(ttlMs) || replay.ttlMs !== ttlMs) {
          return { kind: 'replay_conflict' }
        }

        return { kind: 'replayed', id: replay.id }
      }

      if (this.records.has(record.id)) {
        return { kind: 'duplicate_id' }
      }

      this.records.set(record.id, record)
      this.replays.set(replayKey, {
        id: record.id,
        ttlMs: record.expiresAtMs - record.createdAtMs,
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

  async revoke(id: SecretId, nowMs: number): Promise<RevokeResult | { kind: 'not_found' }> {
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

  async getStatus(id: SecretId, nowMs: number) {
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

function record(ciphertext = new Uint8Array([7, 8, 9])): PreparedSecretRecord {
  const prepared = prepareSecretRecord(generateSecretId(), ciphertext, 100, 900)

  if (!prepared.ok) {
    throw new Error(`failed to prepare test secret: ${prepared.reason}`)
  }

  return prepared.record
}

describe('SecretRepository atomic transition contract', () => {
  it('inserts each identifier only once and never overwrites an existing record', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const original = record()
    const replacement = {
      ...original,
      ciphertext: new Uint8Array([9, 9, 9]),
    } as PreparedSecretRecord

    expect(await repository.create(original, 'replay-original')).toEqual({
      kind: 'created',
      id: original.id,
    })
    expect(await repository.create(replacement, 'replay-replacement')).toEqual({
      kind: 'duplicate_id',
    })

    const consumed = await repository.consume(original.id, 500)
    expect(consumed.kind).toBe('revealed')

    if (consumed.kind === 'revealed') {
      expect(consumed.ciphertext).toEqual(original.ciphertext)
    }
  })

  it('allows only one concurrent create for the same identifier', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()

    const results = await Promise.all([
      repository.create(secret, 'replay-secret'),
      repository.create(secret, 'replay-secret'),
      repository.create(secret, 'replay-secret'),
    ])

    expect(results.filter((result) => result.kind === 'created')).toHaveLength(1)
    expect(results.filter((result) => result.kind === 'replayed')).toHaveLength(2)
    for (const result of results) {
      expect(result.kind === 'created' || result.kind === 'replayed').toBe(true)
      if (result.kind === 'created' || result.kind === 'replayed') {
        expect(result.id).toBe(secret.id)
      }
    }
  })

  it('reuses the original public identifier when the same create request is replayed', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const original = record()
    const replay = record()

    expect(await repository.create(original, 'same-payload')).toEqual({
      kind: 'created',
      id: original.id,
    })
    expect(await repository.create(replay, 'same-payload')).toEqual({
      kind: 'replayed',
      id: original.id,
    })
  })

  it('rejects replaying the same payload key with a different TTL', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const original = record()
    const changedTtl = prepareSecretRecord(
      generateSecretId(),
      original.ciphertext,
      original.createdAtMs,
      800,
    )

    if (!changedTtl.ok) {
      throw new Error(`failed to prepare replay conflict: ${changedTtl.reason}`)
    }

    expect(await repository.create(original, 'same-payload')).toEqual({
      kind: 'created',
      id: original.id,
    })
    expect(await repository.create(changedTtl.record, 'same-payload')).toEqual({
      kind: 'replay_conflict',
    })
  })

  it('allows only one winner when consume calls interleave asynchronously', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const id = secret.id
    await repository.create(secret, 'replay-secret')

    const results = await Promise.all([
      repository.consume(id, 500),
      repository.consume(id, 500),
      repository.consume(id, 500),
    ])

    const winners = results.filter((result) => result.kind === 'revealed')
    const losers = results.filter((result) => result.kind === 'unavailable')

    expect(winners).toHaveLength(1)
    expect(losers).toHaveLength(2)
    expect(losers.every((result) => !('ciphertext' in result))).toBe(true)
    expect((await repository.getStatus(id, 500))?.state).toBe('CONSUMED')
  })

  it('allows consume or revoke to win, but never both', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const id = secret.id
    await repository.create(secret, 'replay-secret')

    const [consume, revoke] = await Promise.all([
      repository.consume(id, 500),
      repository.revoke(id, 500),
    ])

    const consumeWon = consume.kind === 'revealed'
    const revokeWon = revoke.kind === 'revoked'

    expect(Number(consumeWon) + Number(revokeWon)).toBe(1)
    expect((await repository.getStatus(id, 500))?.state).toBe(consumeWon ? 'CONSUMED' : 'REVOKED')

    if (consumeWon) {
      expect(revoke).toEqual({ kind: 'unavailable', state: 'CONSUMED' })
    } else {
      expect(consume).toEqual({ kind: 'unavailable', state: 'REVOKED' })
    }
  })

  it('fails closed when persisted temporal data is malformed', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const id = secret.id
    const malformed = {
      ...secret,
      expiresAtMs: Number.NaN,
    } as PreparedSecretRecord

    expect(await repository.create(malformed, 'replay-malformed')).toEqual({
      kind: 'created',
      id: malformed.id,
    })
    expect(await repository.consume(id, 500)).toEqual({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
    expect((await repository.getStatus(id, 500))?.state).toBe('EXPIRED')
  })

  it('fails closed for an unknown persisted lifecycle state', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const id = secret.id
    const malformed = {
      ...secret,
      state: 'UNKNOWN',
    } as unknown as PreparedSecretRecord

    expect(await repository.create(malformed, 'replay-malformed')).toEqual({
      kind: 'created',
      id: malformed.id,
    })
    expect(await repository.consume(id, 500)).toEqual({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
    expect((await repository.getStatus(id, 500))?.state).toBe('EXPIRED')
  })

  it('never exposes ciphertext through status or revoke operations', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const secret = record()
    const id = secret.id
    await repository.create(secret, 'replay-secret')

    const status = await repository.getStatus(id, 500)
    expect(status?.state).toBe('AVAILABLE')
    expect(status && 'ciphertext' in status).toBe(false)

    const revoked = await repository.revoke(id, 500)
    expect(revoked.kind).toBe('revoked')
    expect('ciphertext' in revoked).toBe(false)
  })
})
