export const SECRET_ID_MIN_ENTROPY_BITS = 128

export const DEFAULT_SECRET_POLICY = {
  defaultTtlMs: 24 * 60 * 60 * 1000,
  maxTtlMs: 7 * 24 * 60 * 60 * 1000,
  maxPayloadBytes: 64 * 1024,
} as const

export type SecretId = string & { readonly __secretId: unique symbol }

export type SecretState = 'AVAILABLE' | 'CONSUMED' | 'EXPIRED' | 'REVOKED'

export interface SecretPolicy {
  defaultTtlMs: number
  maxTtlMs: number
  maxPayloadBytes: number
}

export interface SecretRecord {
  id: SecretId
  ciphertext: Uint8Array
  createdAtMs: number
  expiresAtMs: number
  state: SecretState
}

export interface SecretStatus {
  id: SecretId
  createdAtMs: number
  expiresAtMs: number
  state: SecretState
}

export interface SecretIdGenerator {
  /**
   * Generate an unpredictable, non-enumerable identifier with at least
   * SECRET_ID_MIN_ENTROPY_BITS of cryptographic entropy.
   */
  generate(): SecretId
}

export type CreateSecretValidation =
  | { ok: true; ttlMs: number }
  | { ok: false; reason: 'INVALID_POLICY' | 'INVALID_TTL' | 'PAYLOAD_TOO_LARGE' }

export type CreateResult = { kind: 'created' } | { kind: 'duplicate' }

export type ConsumeResult =
  | { kind: 'revealed'; ciphertext: Uint8Array; status: SecretStatus }
  | { kind: 'unavailable'; state: Exclude<SecretState, 'AVAILABLE'> }

export type RevokeResult =
  | { kind: 'revoked'; status: SecretStatus }
  | { kind: 'unavailable'; state: Exclude<SecretState, 'AVAILABLE'> }

export type ConsumeDecision =
  | { nextState: 'CONSUMED'; result: Extract<ConsumeResult, { kind: 'revealed' }> }
  | {
      nextState: Exclude<SecretState, 'AVAILABLE'>
      result: Extract<ConsumeResult, { kind: 'unavailable' }>
    }

export type RevokeDecision =
  | { nextState: 'REVOKED'; result: Extract<RevokeResult, { kind: 'revoked' }> }
  | {
      nextState: Exclude<SecretState, 'AVAILABLE'>
      result: Extract<RevokeResult, { kind: 'unavailable' }>
    }

export interface SecretRepository {
  /**
   * Atomically insert a new secret. Existing identifiers are never overwritten,
   * including terminal records.
   */
  create(record: SecretRecord): Promise<CreateResult>

  /**
   * Atomically evaluate expiry and transition AVAILABLE -> CONSUMED.
   * Exactly one caller may receive ciphertext.
   */
  consume(id: SecretId, nowMs: number): Promise<ConsumeResult | { kind: 'not_found' }>

  /**
   * Atomically evaluate expiry and transition AVAILABLE -> REVOKED.
   * This operation must never overwrite CONSUMED, EXPIRED, or REVOKED.
   */
  revoke(id: SecretId, nowMs: number): Promise<RevokeResult | { kind: 'not_found' }>

  /**
   * Read lifecycle metadata only. Ciphertext is intentionally unavailable
   * outside the winning consume result. Implementations may atomically record
   * AVAILABLE -> EXPIRED when the deadline has passed.
   */
  getStatus(id: SecretId, nowMs: number): Promise<SecretStatus | undefined>
}

export function validateCreateSecret(
  payloadBytes: number,
  requestedTtlMs: number | undefined,
  policy: SecretPolicy = DEFAULT_SECRET_POLICY,
): CreateSecretValidation {
  if (
    !Number.isSafeInteger(policy.defaultTtlMs) ||
    !Number.isSafeInteger(policy.maxTtlMs) ||
    !Number.isSafeInteger(policy.maxPayloadBytes) ||
    policy.defaultTtlMs <= 0 ||
    policy.maxTtlMs <= 0 ||
    policy.maxPayloadBytes <= 0 ||
    policy.defaultTtlMs > policy.maxTtlMs
  ) {
    return { ok: false, reason: 'INVALID_POLICY' }
  }

  if (
    !Number.isSafeInteger(payloadBytes) ||
    payloadBytes < 0 ||
    payloadBytes > policy.maxPayloadBytes
  ) {
    return { ok: false, reason: 'PAYLOAD_TOO_LARGE' }
  }

  const ttlMs = requestedTtlMs ?? policy.defaultTtlMs
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > policy.maxTtlMs) {
    return { ok: false, reason: 'INVALID_TTL' }
  }

  return { ok: true, ttlMs }
}

export function toSecretStatus(record: SecretRecord): SecretStatus {
  return {
    id: record.id,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    state: record.state,
  }
}

export function effectiveState(record: SecretRecord, nowMs: number): SecretState {
  if (record.state === 'AVAILABLE' && nowMs >= record.expiresAtMs) {
    return 'EXPIRED'
  }

  return record.state
}

export function consumeSecret(record: SecretRecord, nowMs: number): ConsumeDecision {
  const state = effectiveState(record, nowMs)

  if (state !== 'AVAILABLE') {
    return {
      nextState: state,
      result: { kind: 'unavailable', state },
    }
  }

  const status = toSecretStatus({ ...record, state: 'CONSUMED' })
  return {
    nextState: 'CONSUMED',
    result: {
      kind: 'revealed',
      ciphertext: record.ciphertext,
      status,
    },
  }
}

export function revokeSecret(record: SecretRecord, nowMs: number): RevokeDecision {
  const state = effectiveState(record, nowMs)

  if (state !== 'AVAILABLE') {
    return {
      nextState: state,
      result: { kind: 'unavailable', state },
    }
  }

  return {
    nextState: 'REVOKED',
    result: {
      kind: 'revoked',
      status: toSecretStatus({ ...record, state: 'REVOKED' }),
    },
  }
}
