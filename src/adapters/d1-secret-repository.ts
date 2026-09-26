import {
  effectiveState,
  type ConsumeResult,
  type CreateResult,
  type PreparedSecretRecord,
  type RevokeResult,
  type SecretId,
  type SecretRecord,
  type SecretRepository,
  type SecretState,
  type SecretStatus,
} from '../core/secret'

export type D1BindingValue = string | number | null | ArrayBuffer | ArrayBufferView

export interface D1ResultLike<Row = Record<string, unknown>> {
  success: boolean
  results: Row[]
  meta?: {
    changes?: number
  }
}

export interface D1PreparedStatementLike {
  bind(...values: D1BindingValue[]): D1PreparedStatementLike
  run<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>>
  first<Row = Record<string, unknown>>(): Promise<Row | null>
}

export interface D1SessionLike {
  prepare(query: string): D1PreparedStatementLike
  batch(statements: D1PreparedStatementLike[]): Promise<D1ResultLike[]>
}

export interface D1DatabaseLike extends D1SessionLike {
  withSession(constraint?: 'first-primary' | 'first-unconstrained' | string): D1SessionLike
}

interface SecretRow {
  id: string
  ciphertext: unknown
  created_at_ms: number
  expires_at_ms: number
  state: string
}

interface StatusRow {
  id: string
  created_at_ms: number
  expires_at_ms: number
  state: string
}

function randomToken(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function toCiphertextBytes(value: unknown): Uint8Array | undefined {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice()
  }

  if (
    Array.isArray(value) &&
    value.every(
      (byte) => Number.isInteger(byte) && typeof byte === 'number' && byte >= 0 && byte <= 255,
    )
  ) {
    return Uint8Array.from(value)
  }

  return undefined
}

function toRecord(row: SecretRow): SecretRecord | undefined {
  const ciphertext = toCiphertextBytes(row.ciphertext)
  if (!ciphertext) {
    return undefined
  }

  return {
    id: row.id as SecretId,
    ciphertext,
    createdAtMs: row.created_at_ms,
    expiresAtMs: row.expires_at_ms,
    state: row.state as SecretState,
  }
}

function toStatus(row: StatusRow, nowMs: number): SecretStatus {
  const record: SecretRecord = {
    id: row.id as SecretId,
    ciphertext: new Uint8Array(),
    createdAtMs: row.created_at_ms,
    expiresAtMs: row.expires_at_ms,
    state: row.state as SecretState,
  }

  return {
    id: record.id,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    state: effectiveState(record, nowMs),
  }
}

function unavailableState(row: StatusRow, nowMs: number): Exclude<SecretState, 'AVAILABLE'> {
  const state = toStatus(row, nowMs).state
  return state === 'AVAILABLE' ? 'EXPIRED' : state
}

export class D1SecretRepository implements SecretRepository {
  constructor(private readonly db: D1DatabaseLike) {}

  async create(record: PreparedSecretRecord): Promise<CreateResult> {
    const result = await this.db
      .prepare(
        `INSERT OR IGNORE INTO secrets
          (id, ciphertext, created_at_ms, expires_at_ms, state)
         VALUES (?, ?, ?, ?, 'AVAILABLE')`,
      )
      .bind(record.id, record.ciphertext, record.createdAtMs, record.expiresAtMs)
      .run()

    return result.meta?.changes === 1 ? { kind: 'created' } : { kind: 'duplicate' }
  }

  async consume(id: SecretId, nowMs: number): Promise<ConsumeResult | { kind: 'not_found' }> {
    if (!Number.isSafeInteger(nowMs)) {
      return { kind: 'unavailable', state: 'EXPIRED' }
    }

    const session = this.db.withSession('first-primary')
    const token = randomToken()
    const results = await session.batch([
      session
        .prepare(
          `UPDATE secrets
           SET state = 'EXPIRED'
           WHERE id = ? AND state = 'AVAILABLE' AND expires_at_ms <= ?`,
        )
        .bind(id, nowMs),
      session
        .prepare(
          `UPDATE secrets
           SET state = 'CONSUMED', consumed_at_ms = ?, consume_token = ?
           WHERE id = ? AND state = 'AVAILABLE' AND expires_at_ms > ?`,
        )
        .bind(nowMs, token, id, nowMs),
      session
        .prepare(
          `SELECT id, ciphertext, created_at_ms, expires_at_ms, state
           FROM secrets
           WHERE id = ? AND consume_token = ?
           LIMIT 1`,
        )
        .bind(id, token),
      session
        .prepare(
          `UPDATE secrets
           SET consume_token = NULL
           WHERE id = ? AND consume_token = ?`,
        )
        .bind(id, token),
    ])

    const winner = results[2]?.results[0] as unknown as SecretRow | undefined
    if (winner) {
      const record = toRecord(winner)
      const status = toStatus(winner, nowMs)

      if (!record || status.state !== 'CONSUMED') {
        return { kind: 'unavailable', state: 'EXPIRED' }
      }

      return {
        kind: 'revealed',
        ciphertext: record.ciphertext,
        status,
      }
    }

    const row = await session
      .prepare(
        `SELECT id, created_at_ms, expires_at_ms, state
         FROM secrets
         WHERE id = ?
         LIMIT 1`,
      )
      .bind(id)
      .first<StatusRow>()

    if (!row) {
      return { kind: 'not_found' }
    }

    return { kind: 'unavailable', state: unavailableState(row, nowMs) }
  }

  async revoke(id: SecretId, nowMs: number): Promise<RevokeResult | { kind: 'not_found' }> {
    if (!Number.isSafeInteger(nowMs)) {
      return { kind: 'unavailable', state: 'EXPIRED' }
    }

    const session = this.db.withSession('first-primary')
    const results = await session.batch([
      session
        .prepare(
          `UPDATE secrets
           SET state = 'EXPIRED'
           WHERE id = ? AND state = 'AVAILABLE' AND expires_at_ms <= ?`,
        )
        .bind(id, nowMs),
      session
        .prepare(
          `UPDATE secrets
           SET state = 'REVOKED', revoked_at_ms = ?
           WHERE id = ? AND state = 'AVAILABLE' AND expires_at_ms > ?`,
        )
        .bind(nowMs, id, nowMs),
      session
        .prepare(
          `SELECT id, created_at_ms, expires_at_ms, state
           FROM secrets
           WHERE id = ?
           LIMIT 1`,
        )
        .bind(id),
    ])

    const row = results[2]?.results[0] as unknown as StatusRow | undefined
    if (!row) {
      return { kind: 'not_found' }
    }

    const status = toStatus(row, nowMs)
    return status.state === 'REVOKED'
      ? { kind: 'revoked', status }
      : { kind: 'unavailable', state: unavailableState(row, nowMs) }
  }

  async getStatus(id: SecretId, nowMs: number): Promise<SecretStatus | undefined> {
    if (!Number.isSafeInteger(nowMs)) {
      return undefined
    }

    const session = this.db.withSession('first-primary')
    const results = await session.batch([
      session
        .prepare(
          `UPDATE secrets
           SET state = 'EXPIRED'
           WHERE id = ? AND state = 'AVAILABLE' AND expires_at_ms <= ?`,
        )
        .bind(id, nowMs),
      session
        .prepare(
          `SELECT id, created_at_ms, expires_at_ms, state
           FROM secrets
           WHERE id = ?
           LIMIT 1`,
        )
        .bind(id),
    ])

    const row = results[1]?.results[0] as unknown as StatusRow | undefined
    return row ? toStatus(row, nowMs) : undefined
  }
}
