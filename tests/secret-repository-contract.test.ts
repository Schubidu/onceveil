import { describe, expect, it } from 'vitest'

import {
  consumeSecret,
  effectiveState,
  revokeSecret,
  toSecretStatus,
  type ConsumeResult,
  type RevokeResult,
  type SecretId,
  type SecretRecord,
  type SecretRepository,
} from '../src/core/secret'

class AsyncAtomicInMemorySecretRepository implements SecretRepository {
  private readonly records = new Map<SecretId, SecretRecord>()
  private readonly queues = new Map<SecretId, Promise<void>>()

  async create(record: SecretRecord) {
    this.records.set(record.id, record)
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
      const record = this.records.get(id)
      if (!record) {
        return undefined
      }

      const outcome = await mutation(record)
      this.records.set(id, { ...record, state: outcome.nextState })
      return outcome.result
    } finally {
      release?.()
    }
  }
}

function record(id: SecretId): SecretRecord {
  return {
    id,
    ciphertext: new Uint8Array([7, 8, 9]),
    createdAtMs: 100,
    expiresAtMs: 1_000,
    state: 'AVAILABLE',
  }
}

describe('SecretRepository atomic transition contract', () => {
  it('allows only one winner when consume calls interleave asynchronously', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const id = 'consume-race-id' as SecretId
    await repository.create(record(id))

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
    const id = 'consume-revoke-race-id' as SecretId
    await repository.create(record(id))

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

  it('never exposes ciphertext through status or revoke operations', async () => {
    const repository = new AsyncAtomicInMemorySecretRepository()
    const id = 'metadata-test-id' as SecretId
    await repository.create(record(id))

    const status = await repository.getStatus(id, 500)
    expect(status?.state).toBe('AVAILABLE')
    expect(status && 'ciphertext' in status).toBe(false)

    const revoked = await repository.revoke(id, 500)
    expect(revoked.kind).toBe('revoked')
    expect('ciphertext' in revoked).toBe(false)
  })
})
