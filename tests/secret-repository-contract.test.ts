import { describe, expect, it } from 'vitest'

import {
  consumeSecret,
  revokeSecret,
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

    const result = consumeSecret(record, nowMs)
    this.records.set(id, result.record)
    return result
  }

  async revoke(id: SecretId, nowMs: number): Promise<RevokeResult | { kind: 'not_found' }> {
    const record = this.records.get(id)
    if (!record) {
      return { kind: 'not_found' }
    }

    const result = revokeSecret(record, nowMs)
    this.records.set(id, result.record)
    return result
  }

  async get(id: SecretId) {
    return this.records.get(id)
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

    expect(results.filter((result) => result.kind === 'revealed')).toHaveLength(1)
    expect(results.filter((result) => result.kind === 'unavailable')).toHaveLength(2)
    expect((await repository.get(id, 500))?.state).toBe('CONSUMED')
  })
})
