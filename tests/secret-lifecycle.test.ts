import { describe, expect, it } from 'vitest'

import {
  DEFAULT_SECRET_POLICY,
  consumeSecret,
  effectiveState,
  generateSecretId,
  prepareSecretRecord,
  generateSecretId,
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
    expect(first.nextState).toBe('CONSUMED')
    expect(first.result.kind).toBe('revealed')

    if (first.result.kind !== 'revealed') {
      throw new Error('expected reveal')
    }

    expect(first.result.ciphertext).toEqual(new Uint8Array([1, 2, 3]))
    expect(first.result.status.state).toBe('CONSUMED')

    const second = consumeSecret(available({ state: first.nextState }), 600)
    expect(second.result).toEqual({ kind: 'unavailable', state: 'CONSUMED' })
    expect('ciphertext' in second.result).toBe(false)
  })

  it('treats an available secret as expired at its deadline', () => {
    expect(effectiveState(available(), 999)).toBe('AVAILABLE')
    expect(effectiveState(available(), 1_000)).toBe('EXPIRED')
  })

  it.each([
    { record: available({ expiresAtMs: Number.NaN }), nowMs: 500 },
    { record: available({ expiresAtMs: Number.POSITIVE_INFINITY }), nowMs: 500 },
    { record: available({ createdAtMs: Number.NaN }), nowMs: 500 },
    { record: available({ expiresAtMs: 100 }), nowMs: 500 },
    { record: available(), nowMs: Number.NaN },
    { record: available(), nowMs: Number.POSITIVE_INFINITY },
  ])('fails closed for invalid temporal input', ({ record, nowMs }) => {
    expect(effectiveState(record, nowMs)).toBe('EXPIRED')

    const consume = consumeSecret(record, nowMs)
    expect(consume.result).toEqual({ kind: 'unavailable', state: 'EXPIRED' })
    expect('ciphertext' in consume.result).toBe(false)
  })

  it.each(terminalStates)('keeps terminal state %s unchanged', (state) => {
    expect(effectiveState(available({ state }), 2_000)).toBe(state)
  })

  it('fails closed for an unknown persisted lifecycle state', () => {
    const malformed = available({ state: 'UNKNOWN' as SecretState })

    expect(effectiveState(malformed, 500)).toBe('EXPIRED')
    expect(consumeSecret(malformed, 500).result).toEqual({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
    expect(revokeSecret(malformed, 500).result).toEqual({
      kind: 'unavailable',
      state: 'EXPIRED',
    })
  })

  it.each(terminalStates)('never returns ciphertext for %s secrets', (state) => {
    const decision = consumeSecret(available({ state }), 500)
    expect(decision.result).toEqual({ kind: 'unavailable', state })
    expect('ciphertext' in decision.result).toBe(false)
  })

  it('never returns ciphertext for an expired available secret', () => {
    const decision = consumeSecret(available(), 1_000)
    expect(decision.nextState).toBe('EXPIRED')
    expect(decision.result).toEqual({ kind: 'unavailable', state: 'EXPIRED' })
    expect('ciphertext' in decision.result).toBe(false)
  })

  it('revokes an available, unexpired secret without returning ciphertext', () => {
    const decision = revokeSecret(available(), 500)
    expect(decision.nextState).toBe('REVOKED')
    expect(decision.result).toMatchObject({
      kind: 'revoked',
      status: { state: 'REVOKED' },
    })
    expect('ciphertext' in decision.result).toBe(false)
  })

  it.each(terminalStates)('does not revoke terminal state %s', (state) => {
    const decision = revokeSecret(available({ state }), 500)
    expect(decision.nextState).toBe(state)
    expect(decision.result).toEqual({ kind: 'unavailable', state })
    expect('ciphertext' in decision.result).toBe(false)
  })

  it('expires instead of revoking at the expiry deadline', () => {
    const decision = revokeSecret(available(), 1_000)
    expect(decision.nextState).toBe('EXPIRED')
    expect(decision.result).toEqual({ kind: 'unavailable', state: 'EXPIRED' })
  })
})

describe('secret creation policy', () => {
  it('generates a 128-bit secret identifier inside the creation boundary', () => {
    const generated = generateSecretId()

    expect(generated).toMatch(/^[0-9a-f]{32}$/)
  })
  it('prepares an AVAILABLE record with validated payload and derived expiry', () => {
    const generatedId = generateSecretId()
    const result = prepareSecretRecord(generatedId, new Uint8Array([1, 2, 3]), 100, 500)

    expect(result.ok).toBe(true)

    if (result.ok) {
      expect(result.record).toMatchObject({
        id: generatedId,
        createdAtMs: 100,
        expiresAtMs: 600,
        state: 'AVAILABLE',
      })
    }
  })

  it('refuses to prepare records that exceed the payload limit', () => {
    const result = prepareSecretRecord(
      generateSecretId(),
      new Uint8Array(DEFAULT_SECRET_POLICY.maxPayloadBytes + 1),
      100,
      undefined,
    )

    expect(result).toEqual({ ok: false, reason: 'PAYLOAD_TOO_LARGE' })
  })

  it('rejects malformed identifiers at the persistence boundary', () => {
    expect(
      prepareSecretRecord(
        'predictable-id' as SecretId,
        new Uint8Array([1]),
        100,
        undefined,
      ),
    ).toEqual({ ok: false, reason: 'INVALID_ID' })
  })

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

  it.each([null, 0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    'rejects invalid TTL %s',
    (ttlMs) => {
      expect(validateCreateSecret(1024, ttlMs)).toEqual({
        ok: false,
        reason: 'INVALID_TTL',
      })
    },
  )

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
    expect(validateCreateSecret(1, undefined, null)).toEqual({
      ok: false,
      reason: 'INVALID_POLICY',
    })
  })

  it.each([
    {
      defaultTtlMs: DEFAULT_SECRET_POLICY.defaultTtlMs + 1,
      maxTtlMs: DEFAULT_SECRET_POLICY.maxTtlMs,
      maxPayloadBytes: DEFAULT_SECRET_POLICY.maxPayloadBytes,
    },
    {
      defaultTtlMs: DEFAULT_SECRET_POLICY.defaultTtlMs,
      maxTtlMs: DEFAULT_SECRET_POLICY.maxTtlMs + 1,
      maxPayloadBytes: DEFAULT_SECRET_POLICY.maxPayloadBytes,
    },
    {
      defaultTtlMs: DEFAULT_SECRET_POLICY.defaultTtlMs,
      maxTtlMs: DEFAULT_SECRET_POLICY.maxTtlMs,
      maxPayloadBytes: DEFAULT_SECRET_POLICY.maxPayloadBytes + 1,
    },
  ])('rejects policy limits above the safety envelope', (policy) => {
    expect(validateCreateSecret(1, undefined, policy)).toEqual({
      ok: false,
      reason: 'INVALID_POLICY',
    })
  })
})
