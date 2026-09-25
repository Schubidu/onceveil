import { describe, expect, it } from 'vitest'

import {
  DEFAULT_SECRET_POLICY,
  consumeSecret,
  expireSecret,
  revokeSecret,
  type SecretId,
  type SecretRecord,
  validateCreateSecret,
} from '../src/core/secret'

const id = 'test-secret-id' as SecretId

function available(overrides: Partial<SecretRecord> = {}): SecretRecord {
  return {
    id,
    ciphertext: new Uint8Array([1, 2, 3]),
    createdAtMs: 100,
    expiresAtMs: 1_000,
    state: 'AVAILABLE',
    ...overrides,
  }
}

describe('secret lifecycle', () => {
  it('consumes an available secret exactly once', () => {
    const first = consumeSecret(available(), 500)
    expect(first.kind).toBe('revealed')

    if (first.kind !== 'revealed') {
      throw new Error('expected reveal')
    }

    expect(first.record.state).toBe('CONSUMED')
    expect(first.ciphertext).toEqual(new Uint8Array([1, 2, 3]))

    const second = consumeSecret(first.record, 600)
    expect(second).toMatchObject({ kind: 'unavailable', state: 'CONSUMED' })
  })

  it('expires an available secret at its deadline', () => {
    expect(expireSecret(available(), 999).state).toBe('AVAILABLE')
    expect(expireSecret(available(), 1_000).state).toBe('EXPIRED')
  })

  it.each(['CONSUMED', 'EXPIRED', 'REVOKED'] as const)(
    'never returns ciphertext for %s secrets',
    (state) => {
      const result = consumeSecret(available({ state }), 500)
      expect(result).toMatchObject({ kind: 'unavailable', state })
    },
  )

  it('never returns ciphertext for an expired available secret', () => {
    const result = consumeSecret(available(), 1_000)
    expect(result).toMatchObject({ kind: 'unavailable', state: 'EXPIRED' })
  })

  it('revokes only an available, unexpired secret', () => {
    expect(revokeSecret(available(), 500)).toMatchObject({
      kind: 'revoked',
      record: { state: 'REVOKED' },
    })
    expect(revokeSecret(available({ state: 'CONSUMED' }), 500)).toMatchObject({
      kind: 'unavailable',
      state: 'CONSUMED',
    })
    expect(revokeSecret(available(), 1_000)).toMatchObject({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
  })
})

describe('secret creation policy', () => {
  it('uses the safe default TTL when none is requested', () => {
    expect(validateCreateSecret(1024, undefined)).toEqual({
      ok: true,
      ttlMs: DEFAULT_SECRET_POLICY.defaultTtlMs,
    })
  })

  it('rejects TTLs beyond the configured maximum', () => {
    expect(validateCreateSecret(1024, DEFAULT_SECRET_POLICY.maxTtlMs + 1)).toEqual({
      ok: false,
      reason: 'INVALID_TTL',
    })
  })

  it('rejects payloads beyond the configured maximum', () => {
    expect(validateCreateSecret(DEFAULT_SECRET_POLICY.maxPayloadBytes + 1, undefined)).toEqual({
      ok: false,
      reason: 'PAYLOAD_TOO_LARGE',
    })
  })

  it('fails closed for invalid policy configuration', () => {
    expect(
      validateCreateSecret(1, undefined, {
        defaultTtlMs: 10,
        maxTtlMs: 5,
        maxPayloadBytes: 1,
      }),
    ).toEqual({ ok: false, reason: 'INVALID_POLICY' })
  })
})
