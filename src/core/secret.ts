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

export type ConsumeResult =
  | { kind: 'revealed'; ciphertext: Uint8Array; record: SecretRecord }
  | { kind: 'unavailable'; state: Exclude<SecretState, 'AVAILABLE'>; record: SecretRecord }

export type RevokeResult =
  | { kind: 'revoked'; record: SecretRecord }
  | { kind: 'unavailable'; state: Exclude<SecretState, 'AVAILABLE'>; record: SecretRecord }

export interface SecretRepository {
  create(record: SecretRecord): Promise<void>

  /**
   * Atomically transition AVAILABLE -> CONSUMED and return ciphertext only to
   * the single caller that wins that transition.
   */
  consume(id: SecretId, nowMs: number): Promise<ConsumeResult | { kind: 'not_found' }>

  revoke(id: SecretId, nowMs: number): Promise<RevokeResult | { kind: 'not_found' }>

  get(id: SecretId, nowMs: number): Promise<SecretRecord | undefined>
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

  if (!Number.isSafeInteger(payloadBytes) || payloadBytes < 0 || payloadBytes > policy.maxPayloadBytes) {
    return { ok: false, reason: 'PAYLOAD_TOO_LARGE' }
  }

  const ttlMs = requestedTtlMs ?? policy.defaultTtlMs
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > policy.maxTtlMs) {
    return { ok: false, reason: 'INVALID_TTL' }
  }

  return { ok: true, ttlMs }
}

export function expireSecret(record: SecretRecord, nowMs: number): SecretRecord {
  if (record.state !== 'AVAILABLE' || nowMs < record.expiresAtMs) {
    return record
  }

  return { ...record, state: 'EXPIRED' }
}

export function consumeSecret(record: SecretRecord, nowMs: number): ConsumeResult {
  const current = expireSecret(record, nowMs)

  if (current.state !== 'AVAILABLE') {
    return { kind: 'unavailable', state: current.state, record: current }
  }

  const consumed = { ...current, state: 'CONSUMED' as const }
  return { kind: 'revealed', ciphertext: consumed.ciphertext, record: consumed }
}

export function revokeSecret(record: SecretRecord, nowMs: number): RevokeResult {
  const current = expireSecret(record, nowMs)

  if (current.state !== 'AVAILABLE') {
    return { kind: 'unavailable', state: current.state, record: current }
  }

  return { kind: 'revoked', record: { ...current, state: 'REVOKED' } }
}
