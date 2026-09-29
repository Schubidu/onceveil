import type { D1DatabaseLike } from './d1-secret-repository'
import {
  isValidMcpFlowId,
  isValidMcpHash,
  type CompleteMcpHandoffResult,
  type McpHandoffAction,
  type McpHandoffRecord,
  type McpHandoffRepository,
  type McpHandoffState,
  type McpFlowId,
  type SealedMcpValue,
} from '../core/mcp-handoff'
import { isValidOwnerCapabilityHash } from '../core/owner-capability'
import { isValidRevealAuthorization } from '../core/share-capability'
import { isValidSecretId } from '../core/secret'

interface McpHandoffRow {
  flow_id: string
  action: string
  state: string
  handoff_token_hash: string
  handoff_token_nonce: string
  handoff_token_ciphertext: string
  created_at_ms: number
  handoff_expires_at_ms: number
  completed_at_ms: number | null
  secret_id: string | null
  owner_key_hash: string | null
}

const REDACTED_HANDOFF_TOKEN_HASH = '0'.repeat(64)

const SELECT_HANDOFF = [
  'SELECT',
  '  flow_id,',
  '  action,',
  '  state,',
  '  handoff_token_hash,',
  '  handoff_token_nonce,',
  '  handoff_token_ciphertext,',
  '  created_at_ms,',
  '  handoff_expires_at_ms,',
  '  completed_at_ms,',
  '  secret_id,',
  '  owner_key_hash',
  'FROM mcp_handoffs',
].join('\n')

function isAction(value: string): value is McpHandoffAction {
  return value === 'create' || value === 'reveal'
}

function isState(value: string): value is McpHandoffState {
  return value === 'PENDING' || value === 'COMPLETED'
}

function sealedValue(nonce: unknown, ciphertext: unknown): SealedMcpValue | undefined {
  if (
    typeof nonce !== 'string' ||
    nonce.length === 0 ||
    typeof ciphertext !== 'string' ||
    ciphertext.length === 0
  ) {
    return undefined
  }

  return { nonce, ciphertext }
}

function toRecord(row: McpHandoffRow): McpHandoffRecord | undefined {
  if (
    !isValidMcpFlowId(row.flow_id) ||
    !isAction(row.action) ||
    !isState(row.state) ||
    !isValidMcpHash(row.handoff_token_hash) ||
    !Number.isSafeInteger(row.created_at_ms) ||
    !Number.isSafeInteger(row.handoff_expires_at_ms) ||
    row.handoff_expires_at_ms <= row.created_at_ms
  ) {
    return undefined
  }

  if (row.completed_at_ms !== null && !Number.isSafeInteger(row.completed_at_ms)) {
    return undefined
  }

  if (
    (row.state === 'PENDING' && row.completed_at_ms !== null) ||
    (row.state === 'COMPLETED' && row.completed_at_ms === null)
  ) {
    return undefined
  }

  const handoffToken = sealedValue(row.handoff_token_nonce, row.handoff_token_ciphertext)
  if (row.state === 'PENDING' && !handoffToken) {
    return undefined
  }

  const record: McpHandoffRecord = {
    flowId: row.flow_id,
    action: row.action,
    state: row.state,
    handoffTokenHash: row.handoff_token_hash,
    ...(handoffToken ? { handoffToken } : {}),
    createdAtMs: row.created_at_ms,
    handoffExpiresAtMs: row.handoff_expires_at_ms,
    ...(row.completed_at_ms === null ? {} : { completedAtMs: row.completed_at_ms }),
  }

  if (row.secret_id !== null) {
    if (!isValidSecretId(row.secret_id)) {
      return undefined
    }
    record.secretId = row.secret_id
  }

  if (row.owner_key_hash !== null) {
    if (!isValidOwnerCapabilityHash(row.owner_key_hash)) {
      return undefined
    }
    record.ownerKeyHash = row.owner_key_hash
  }

  if (row.state === 'PENDING' && (record.secretId || record.ownerKeyHash)) {
    return undefined
  }

  if (row.state === 'COMPLETED') {
    if (!record.secretId) {
      return undefined
    }
    if (row.action === 'create' && !record.ownerKeyHash) {
      return undefined
    }
    if (row.action === 'reveal' && record.ownerKeyHash) {
      return undefined
    }
  }

  return record
}

export class D1McpHandoffRepository implements McpHandoffRepository {
  constructor(private readonly db: D1DatabaseLike) {}

  async create(record: McpHandoffRecord): Promise<boolean> {
    if (!record.handoffToken) {
      return false
    }

    const session = this.db.withSession('first-primary')
    const scrub = await session
      .prepare(
        `UPDATE mcp_handoffs
         SET handoff_token_hash = ?
         WHERE handoff_expires_at_ms <= ?
           AND state = 'COMPLETED'
           AND action = 'create'`,
      )
      .bind(REDACTED_HANDOFF_TOKEN_HASH, record.createdAtMs)
      .run()
    const cleanup = await session
      .prepare(
        `DELETE FROM mcp_handoffs
         WHERE handoff_expires_at_ms <= ?
           AND (state = 'PENDING' OR action = 'reveal')`,
      )
      .bind(record.createdAtMs)
      .run()

    if (!scrub.success || !cleanup.success) {
      return false
    }

    const result = await session
      .prepare(
        'INSERT OR IGNORE INTO mcp_handoffs (' +
          'flow_id, action, state, handoff_token_hash, handoff_token_nonce, ' +
          'handoff_token_ciphertext, created_at_ms, handoff_expires_at_ms' +
          ") VALUES (?, ?, 'PENDING', ?, ?, ?, ?, ?)",
      )
      .bind(
        record.flowId,
        record.action,
        record.handoffTokenHash,
        record.handoffToken.nonce,
        record.handoffToken.ciphertext,
        record.createdAtMs,
        record.handoffExpiresAtMs,
      )
      .run()

    return result.success && result.meta?.changes === 1
  }

  async get(flowId: McpFlowId): Promise<McpHandoffRecord | undefined> {
    const session = this.db.withSession('first-primary')
    const row = await session
      .prepare(`${SELECT_HANDOFF} WHERE flow_id = ? LIMIT 1`)
      .bind(flowId)
      .first<McpHandoffRow>()

    return row ? toRecord(row) : undefined
  }

  async getAuthorized(
    flowId: McpFlowId,
    handoffTokenHash: string,
    nowMs: number,
  ): Promise<McpHandoffRecord | undefined> {
    if (!isValidMcpHash(handoffTokenHash) || !Number.isSafeInteger(nowMs)) {
      return undefined
    }

    const session = this.db.withSession('first-primary')
    const row = await session
      .prepare(
        SELECT_HANDOFF +
          ' WHERE flow_id = ? AND handoff_token_hash = ? AND handoff_expires_at_ms > ? LIMIT 1',
      )
      .bind(flowId, handoffTokenHash, nowMs)
      .first<McpHandoffRow>()

    return row ? toRecord(row) : undefined
  }

  async completeCreate(
    flowId: McpFlowId,
    handoffTokenHash: string,
    secretId: import('../core/secret').SecretId,
    ownerKeyHash: import('../core/owner-capability').OwnerCapabilityHash,
    nowMs: number,
  ): Promise<CompleteMcpHandoffResult> {
    const session = this.db.withSession('first-primary')
    const results = await session.batch([
      session
        .prepare(
          'UPDATE mcp_handoffs SET ' +
            "state = 'COMPLETED', completed_at_ms = ?, secret_id = ?, owner_key_hash = ?, " +
            "handoff_token_nonce = '', handoff_token_ciphertext = '' " +
            "WHERE flow_id = ? AND action = 'create' AND state = 'PENDING' " +
            'AND handoff_token_hash = ? AND handoff_expires_at_ms > ?',
        )
        .bind(nowMs, secretId, ownerKeyHash, flowId, handoffTokenHash, nowMs),
      session
        .prepare(
          SELECT_HANDOFF +
            " WHERE flow_id = ? AND action = 'create' AND handoff_token_hash = ? LIMIT 1",
        )
        .bind(flowId, handoffTokenHash),
    ])

    if (results[0]?.success && results[0]?.meta?.changes === 1) {
      return 'completed'
    }

    const row = results[1]?.results[0] as unknown as McpHandoffRow | undefined
    const existing = row ? toRecord(row) : undefined
    return existing?.state === 'COMPLETED' &&
      existing.secretId === secretId &&
      existing.ownerKeyHash === ownerKeyHash
      ? 'replayed'
      : 'unavailable'
  }

  async completeReveal(
    flowId: McpFlowId,
    handoffTokenHash: string,
    secretId: import('../core/secret').SecretId,
    revealAuthorization: string,
    nowMs: number,
  ): Promise<CompleteMcpHandoffResult> {
    if (!isValidRevealAuthorization(revealAuthorization) || !Number.isSafeInteger(nowMs)) {
      return 'unavailable'
    }

    const session = this.db.withSession('first-primary')
    const results = await session.batch([
      session
        .prepare(
          "UPDATE mcp_handoffs SET state = 'COMPLETED', completed_at_ms = ?, secret_id = ?, " +
            "handoff_token_nonce = '', handoff_token_ciphertext = '' " +
            "WHERE flow_id = ? AND action = 'reveal' AND state = 'PENDING' " +
            'AND handoff_token_hash = ? AND handoff_expires_at_ms > ? ' +
            'AND EXISTS (' +
            'SELECT 1 FROM secrets ' +
            "WHERE id = ? AND replay_key = ? AND state = 'AVAILABLE' AND expires_at_ms > ?" +
            ')',
        )
        .bind(
          nowMs,
          secretId,
          flowId,
          handoffTokenHash,
          nowMs,
          secretId,
          revealAuthorization,
          nowMs,
        ),
      session
        .prepare(
          SELECT_HANDOFF +
            " WHERE flow_id = ? AND action = 'reveal' AND handoff_token_hash = ? LIMIT 1",
        )
        .bind(flowId, handoffTokenHash),
    ])

    if (results[0]?.success && results[0]?.meta?.changes === 1) {
      return 'completed'
    }

    const row = results[1]?.results[0] as unknown as McpHandoffRow | undefined
    const existing = row ? toRecord(row) : undefined
    return existing?.state === 'COMPLETED' && existing.secretId === secretId
      ? 'replayed'
      : 'unavailable'
  }
}
