import { describe, expect, it } from 'vitest'

import { D1SecretRepository } from '../src/adapters/d1-secret-repository'
import { NodeSqliteDatabase } from '../src/adapters/node-sqlite-database'
import { applySqliteMigrations } from '../src/adapters/sqlite-migrations'
import { encryptedShareForCreate } from '../src/browser/secret-create-retry'
import { DEFAULT_BRANDING } from '../src/core/branding'
import type { SecretId } from '../src/core/secret'
import {
  completeMcpHandoffResponse,
  mcpHandoffInfoResponse,
} from '../src/runtime/mcp-handoff-http'
import { createMcpHandoff, mcpHandoffUrl } from '../src/runtime/mcp-service'
import type { OnceveilRequestContext } from '../src/runtime/request-context'
import { createSecretResponse } from '../src/runtime/secret-http'

const STORAGE_KEY = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)
const SECRET_ID = 'e'.repeat(32) as SecretId

function database(): NodeSqliteDatabase {
  const db = new NodeSqliteDatabase(':memory:')
  applySqliteMigrations(db)
  return db
}

function context(db: NodeSqliteDatabase): OnceveilRequestContext {
  return {
    branding: DEFAULT_BRANDING,
    secretDatabase: db,
    databaseEnvironment: 'markerless',
    revealProtection: { provider: 'noop' },
    mcp: {
      status: 'enabled',
      authToken: 'a'.repeat(32),
      storageKey: STORAGE_KEY,
      publicOrigin: 'https://onceveil.test',
    },
  }
}

function tokenFrom(url: string): string {
  const parsed = new URL(url)
  const match = /^#v1\.([0-9a-f]{64})$/.exec(parsed.hash)
  if (!match) {
    throw new Error('missing test handoff token')
  }
  return match[1]
}

function request(flowId: string, token: string, init: RequestInit = {}): Request {
  return new Request(`https://onceveil.test/api/mcp/handoffs/${flowId}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.headers ?? {}),
    },
  })
}

describe('MCP browser handoff HTTP boundary', () => {
  it('requires the matching live token and refuses reopening after completion', async () => {
    const db = database()
    try {
      const runtime = context(db)
      const nowMs = Date.now()
      const handoff = await createMcpHandoff(runtime, 'create', nowMs)
      const token = tokenFrom(await mcpHandoffUrl(runtime, handoff))

      const pending = await mcpHandoffInfoResponse(
        request(handoff.flowId, token),
        handoff.flowId,
        runtime,
        nowMs + 1,
      )
      expect(pending.status).toBe(200)
      await expect(pending.json()).resolves.toMatchObject({ action: 'create' })

      const wrong = await mcpHandoffInfoResponse(
        request(handoff.flowId, '0'.repeat(64)),
        handoff.flowId,
        runtime,
        nowMs + 1,
      )
      expect(wrong.status).toBe(404)

      const encrypted = await encryptedShareForCreate('browser-only owner capability', undefined)
      const created = await createSecretResponse(
        new Request('https://onceveil.test/api/secrets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            payload: encrypted.encrypted.payload,
            ownerKeyHash: encrypted.ownerCapabilityHash,
          }),
        }),
        new D1SecretRepository(db),
        nowMs,
        () => SECRET_ID,
      )
      expect(created.status).toBe(201)

      const body = JSON.stringify({
        secretId: SECRET_ID,
        ownerKeyHash: encrypted.ownerCapabilityHash,
      })
      const firstCompletion = await completeMcpHandoffResponse(
        request(handoff.flowId, token, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        }),
        handoff.flowId,
        runtime,
        nowMs + 2,
      )
      expect(firstCompletion.status).toBe(200)

      const reopened = await mcpHandoffInfoResponse(
        request(handoff.flowId, token),
        handoff.flowId,
        runtime,
        nowMs + 3,
      )
      expect(reopened.status).toBe(410)
      await expect(reopened.json()).resolves.toEqual({ error: 'completed' })

      const retry = await completeMcpHandoffResponse(
        request(handoff.flowId, token, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        }),
        handoff.flowId,
        runtime,
        nowMs + 3,
      )
      expect(retry.status).toBe(200)
    } finally {
      db.close()
    }
  })

  it('rejects expired browser capabilities without changing handoff state', async () => {
    const db = database()
    try {
      const runtime = context(db)
      const handoff = await createMcpHandoff(runtime, 'reveal', 1_000)
      const token = tokenFrom(await mcpHandoffUrl(runtime, handoff))

      const info = await mcpHandoffInfoResponse(
        request(handoff.flowId, token),
        handoff.flowId,
        runtime,
        handoff.handoffExpiresAtMs,
      )
      expect(info.status).toBe(404)

      const complete = await completeMcpHandoffResponse(
        request(handoff.flowId, token, { method: 'POST' }),
        handoff.flowId,
        runtime,
        handoff.handoffExpiresAtMs,
      )
      expect(complete.status).toBe(404)

      const row = await db
        .prepare('SELECT state FROM mcp_handoffs WHERE flow_id = ?')
        .bind(handoff.flowId)
        .first<{ state: string }>()
      expect(row?.state).toBe('PENDING')
    } finally {
      db.close()
    }
  })
})
