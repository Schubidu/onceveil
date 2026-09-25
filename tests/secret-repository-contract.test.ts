import { describe, expect, it } from 'vitest'

import {
  consumeSecret,
  expireSecret,
  revokeSecret,
  toSecretStatus,
  type ConsumeResult,
  type RevokeResult,
  type SecretId,
  type SecretRecord,
  type SecretRepository,
} from '../src/core/secret'

class AtomicInMemorySecretRepository implements SecretRepository {
  private readonly records = new Map<SecretId, SecretRecord>()

  async create(record: SecretRecord) {
    this.records.set(record.id, record)
  }

  async consume(id: SecretId, nowMs: number): Promise<ConsumeResult | { kind: 'not_found' }> {
    const record = this.records.get(id)
    if (!record) {
      return { kind: 'not_found' }
    }

    const transition = consumeSecret(record, nowMs)
    this.records.set(id, transition.record)
    return transition.result
  }

  async revoke(id: SecretId, nowMs: number): Promise<RevokeResult | { kind: 'not_found' }> {
    const record = this.records.get(id)
    if (!record) {
      return { kind: 'not_found' }
    }

    const transition = revokeSecret(record, nowMs)
    this.records.set(id, transition.record)
    return transition.result
  }

  async getStatus(id: SecretId, nowMs: number) {
    const record = this.records.get(id)
    if (!record) {
      return undefined
    }

    const current = expireSecret(record, nowMs)
    this.records.set(id, current)
    return toSecretStatus(current)
  }
}

describe('SecretRepository atomic consume contract', () => {
  it('allows only one winner for concurrent consume attempts', async () => {
    const repository = new AtomicInMemorySecretRepository()
    const id = 'concurrency-test-id' as SecretId

    await repository.create({
      id,
      ciphertext: new Uint8Array([7, 8, 9]),
      createdAtMs: 100,
      expiresAtMs: 1_000,
      state: 'AVAILABLE',
    })

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

  it('never exposes ciphertext through status or revoke operations', async () => {
    const repository = new AtomicInMemorySecretRepository()
    const id = 'metadata-test-id' as SecretId

    await repository.create({
      id,
      ciphertext: new Uint8Array([4, 5, 6]),
      createdAtMs: 100,
      expiresAtMs: 1_000,
      state: 'AVAILABLE',
    })

    const status = await repository.getStatus(id, 500)
    expect(status?.state).toBe('AVAILABLE')
    expect(status && 'ciphertext' in status).toBe(false)

    const revoked = await repository.revoke(id, 500)
    expect(revoked.kind).toBe('revoked')
    expect('ciphertext' in revoked).toBe(false)
  })
})
