export const SECRET_ID_MIN_ENTROPY_BITS = 128

export const DEFAULT_SECRET_POLICY = {
  defaultTtlMs: 24 * 60 * 60 * 1000,
  maxTtlMs: 7 * 24 * 60 * 60 * 1000,
  maxPayloadBytes: 64 * 1024,
} as const

export type SecretId = string & { readonly __secretId: unique symbol }

const SECRET_ID_PATTERN = /^[0-9a-f]{32}$/

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

declare const preparedSecretRecord: unique symbol

export type PreparedSecretRecord = SecretRecord & {
  readonly [preparedSecretRecord]: true
}

export interface SecretStatus {
  id: SecretId
  createdAtMs: number
  expiresAtMs: number
  state: SecretState
}

export function generateSecretId(): SecretId {
  const bytes = new Uint8Array(SECRET_ID_MIN_ENTROPY_BITS / 8)
  crypto.getRandomValues(bytes)

  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('') as SecretId
}

export function isValidSecretId(value: string): value is SecretId {
  return SECRET_ID_PATTERN.test(value)
}

function isSecretState(value: unknown): value is SecretState {
  return value === 'AVAILABLE' || value === 'CONSUMED' || value === 'EXPIRED' || value === 'REVOKED'
}

export type CreateSecretValidation =
  | { ok: true; ttlMs: number }
  | {
      ok: false
      reason: 'INVALID_ID' | 'INVALID_POLICY' | 'INVALID_TTL' | 'PAYLOAD_TOO_LARGE'
    }

export type CreateResult =
  | { kind: 'created'; id: SecretId }
  | { kind: 'replayed'; id: SecretId }
  | { kind: 'replay_conflict' }
  | { kind: 'duplicate_id' }

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
   * including terminal records. Replaying the same canonical encrypted payload
   * with the same TTL returns the original public identifier instead of creating
   * another row. A replay with different create semantics fails closed.
   */
  create(
    record: PreparedSecretRecord,
    replayKey: string,
    ownerKeyHash: string,
  ): Promise<CreateResult>

  /**
   * Atomically evaluate expiry and transition AVAILABLE -> CONSUMED.
   * Exactly one caller may receive ciphertext.
   */
  consume(id: SecretId, nowMs: number): Promise<ConsumeResult | { kind: 'not_found' }>

  /**
   * Atomically evaluate expiry and transition AVAILABLE -> REVOKED for the
   * matching owner capability hash. A wrong capability is indistinguishable
   * from an unknown identifier.
   */
  revoke(
    id: SecretId,
    ownerKeyHash: string,
    nowMs: number,
  ): Promise<RevokeResult | { kind: 'not_found' }>

  /**
   * Read lifecycle metadata only for the matching owner capability hash.
   * Ciphertext is intentionally unavailable outside the winning consume result.
   * Implementations may atomically record AVAILABLE -> EXPIRED when the deadline
   * has passed. A wrong capability is indistinguishable from an unknown id.
   */
  getStatus(
    id: SecretId,
    ownerKeyHash: string,
    nowMs: number,
  ): Promise<SecretStatus | undefined>
}

export function validateCreateSecret(
  payloadBytes: number,
  requestedTtlMs: number | null | undefined,
  policy: SecretPolicy | null | undefined = DEFAULT_SECRET_POLICY,
): CreateSecretValidation {
  if (
    policy == null ||
    !Number.isSafeInteger(policy.defaultTtlMs) ||
    !Number.isSafeInteger(policy.maxTtlMs) ||
    !Number.isSafeInteger(policy.maxPayloadBytes) ||
    policy.defaultTtlMs <= 0 ||
    policy.maxTtlMs <= 0 ||
    policy.maxPayloadBytes <= 0 ||
    policy.defaultTtlMs > policy.maxTtlMs ||
    policy.defaultTtlMs > DEFAULT_SECRET_POLICY.defaultTtlMs ||
    policy.maxTtlMs > DEFAULT_SECRET_POLICY.maxTtlMs ||
    policy.maxPayloadBytes > DEFAULT_SECRET_POLICY.maxPayloadBytes
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

  const ttlMs = requestedTtlMs === undefined ? policy.defaultTtlMs : requestedTtlMs
  if (
    typeof ttlMs !== 'number' ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs <= 0 ||
    ttlMs > policy.maxTtlMs
  ) {
    return { ok: false, reason: 'INVALID_TTL' }
  }

  return { ok: true, ttlMs }
}

export function prepareSecretRecord(
  id: SecretId,
  ciphertext: Uint8Array,
  createdAtMs: number,
  requestedTtlMs: number | null | undefined,
  policy: SecretPolicy | null | undefined = DEFAULT_SECRET_POLICY,
): { ok: true; record: PreparedSecretRecord } | Extract<CreateSecretValidation, { ok: false }> {
  if (!isValidSecretId(id)) {
    return { ok: false, reason: 'INVALID_ID' }
  }

  const validation = validateCreateSecret(ciphertext.byteLength, requestedTtlMs, policy)
  if (!validation.ok) {
    return validation
  }

  const expiresAtMs = createdAtMs + validation.ttlMs
  if (!Number.isSafeInteger(createdAtMs) || !Number.isSafeInteger(expiresAtMs)) {
    return { ok: false, reason: 'INVALID_TTL' }
  }

  return {
    ok: true,
    record: {
      id,
      ciphertext,
      createdAtMs,
      expiresAtMs,
      state: 'AVAILABLE',
    } as PreparedSecretRecord,
  }
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
  if (!isSecretState(record.state)) {
    return 'EXPIRED'
  }

  if (record.state !== 'AVAILABLE') {
    return record.state
  }

  if (
    !Number.isSafeInteger(nowMs) ||
    !Number.isSafeInteger(record.createdAtMs) ||
    !Number.isSafeInteger(record.expiresAtMs) ||
    record.expiresAtMs <= record.createdAtMs ||
    nowMs >= record.expiresAtMs
  ) {
    return 'EXPIRED'
  }

  return 'AVAILABLE'
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
