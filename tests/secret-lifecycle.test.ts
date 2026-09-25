import { describe, expect, it } from 'vitest'

import {
  DEFAULT_SECRET_POLICY,
  consumeSecret,
  expireSecret,
  revokeSecret,
  type SecretId,
  type SecretRecord,
  type SecretState,
  validateCreateSecret,
} from '../src/core/secret'

const id = 'test-secret-id' as SecretId
const terminalStates: Exclude<SecretState, 'AVAILABLE'>[] = ['CONSUMED', 'EXPIRED', 'REVOKED']

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
    expect(first.result.kind).toBe('revealed')
    expect(first.record.state).toBe('CONSUMED')

    if (first.result.kind !== 'revealed') {
      throw new Error('expected reveal')
    }

    expect(first.result.ciphertext).toEqual(new Uint8Array([1, 2, 3]))
    expect(first.result.status.state).toBe('CONSUMED')

    const second = consumeSecret(first.record, 600)
    expect(second.result).toEqual({ kind: 'unavailable', state: 'CONSUMED' })
    expect('ciphertext' in second.result).toBe(false)
  })

  it('expires an available secret at its deadline', () => {
    expect(expireSecret(available(), 999).state).toBe('AVAILABLE')
    expect(expireSecret(available(), 1_000).state).toBe('EXPIRED')
  })

  it.each(terminalStates)('keeps terminal state %s unchanged on expiration checks', (state) => {
    expect(expireSecret(available({ state }), 2_000).state).toBe(state)
  })

  it.each(terminalStates)('never returns ciphertext for %s secrets', (state) => {
    const transition = consumeSecret(available({ state }), 500)
    expect(transition.result).toEqual({ kind: 'unavailable', state })
    expect('ciphertext' in transition.result).toBe(false)
  })

  it('never returns ciphertext for an expired available secret', () => {
    const transition = consumeSecret(available(), 1_000)
    expect(transition.result).toEqual({ kind: 'unavailable', state: 'EXPIRED' })
    expect('ciphertext' in transition.result).toBe(false)
  })

  it('revokes an available, unexpired secret without returning ciphertext', () => {
    const transition = revokeSecret(available(), 500)
    expect(transition.record.state).toBe('REVOKED')
    expect(transition.result).toMatchObject({
      kind: 'revoked',
      status: { state: 'REVOKED' },
    })
    expect('ciphertext' in transition.result).toBe(false)
  })

  it.each(terminalStates)('does not revoke terminal state %s', (state) => {
    const transition = revokeSecret(available({ state }), 500)
    expect(transition.result).toEqual({ kind: 'unavailable', state })
    expect('ciphertext' in transition.result).toBe(false)
  })

  it('expires instead of revoking at the expiry deadline', () => {
    const transition = revokeSecret(available(), 1_000)
    expect(transition.record.state).toBe('EXPIRED')
    expect(transition.result).toEqual({ kind: 'unavailable', state: 'EXPIRED' })
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

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('rejects invalid TTL %s', (ttlMs) => {
    expect(validateCreateSecret(1024, ttlMs)).toEqual({
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
