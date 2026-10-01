import { describe, expect, it } from 'vitest'

import { D1SecretRepository } from '../src/adapters/d1-secret-repository'
import { NodeSqliteDatabase } from '../src/adapters/node-sqlite-database'
import { applySqliteMigrations } from '../src/adapters/sqlite-migrations'
import { revealAuthorizationFromFragment } from '../src/browser/secret-crypto'
import { encryptedShareForCreate } from '../src/browser/secret-create-retry'
import { DEFAULT_BRANDING } from '../src/core/branding'
import type { SecretId } from '../src/core/secret'
import {
  completeMcpHandoffResponse,
  MAX_MCP_HANDOFF_COMPLETION_BYTES,
  mcpHandoffInfoResponse,
} from '../src/runtime/mcp-handoff-http'
import { createMcpHandoff, mcpHandoffUrl } from '../src/runtime/mcp-service'
import type { OnceveilRequestContext } from '../src/runtime/request-context'
import { createSecretResponse } from '../src/runtime/secret-http'

const STORAGE_KEY = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)
const SECRET_ID = 'e'.repeat(32) as SecretId
const SECOND_SECRET_ID = 'd'.repeat(32) as SecretId

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

  it('requires possession of a valid share capability before completing a reveal handoff', async () => {
    const db = database()
    try {
      const runtime = context(db)
      const nowMs = Date.now()
      const encrypted = await encryptedShareForCreate('still browser protected', undefined)
      const secrets = new D1SecretRepository(db)
      const created = await createSecretResponse(
        new Request('https://onceveil.test/api/secrets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            payload: encrypted.encrypted.payload,
            ownerKeyHash: encrypted.ownerCapabilityHash,
          }),
        }),
        secrets,
        nowMs,
        () => SECRET_ID,
      )
      expect(created.status).toBe(201)

      const handoff = await createMcpHandoff(runtime, 'reveal', nowMs)
      const token = tokenFrom(await mcpHandoffUrl(runtime, handoff))

      const tokenOnly = await completeMcpHandoffResponse(
        request(handoff.flowId, token, { method: 'POST' }),
        handoff.flowId,
        runtime,
        nowMs + 1,
      )
      expect(tokenOnly.status).toBe(400)

      const invalid = await completeMcpHandoffResponse(
        request(handoff.flowId, token, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            secretId: SECRET_ID,
            revealAuthorization: '0'.repeat(64),
          }),
        }),
        handoff.flowId,
        runtime,
        nowMs + 2,
      )
      expect(invalid.status).toBe(404)

      const pending = await db
        .prepare('SELECT state FROM mcp_handoffs WHERE flow_id = ?')
        .bind(handoff.flowId)
        .first<{ state: string }>()
      expect(pending?.state).toBe('PENDING')

      const completed = await completeMcpHandoffResponse(
        request(handoff.flowId, token, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            secretId: SECRET_ID,
            revealAuthorization: revealAuthorizationFromFragment(encrypted.encrypted.fragment),
          }),
        }),
        handoff.flowId,
        runtime,
        nowMs + 3,
      )
      expect(completed.status).toBe(200)

      const secondEncrypted = await encryptedShareForCreate('different share', undefined)
      const secondCreated = await createSecretResponse(
        new Request('https://onceveil.test/api/secrets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            payload: secondEncrypted.encrypted.payload,
            ownerKeyHash: secondEncrypted.ownerCapabilityHash,
          }),
        }),
        secrets,
        nowMs + 4,
        () => SECOND_SECRET_ID,
      )
      expect(secondCreated.status).toBe(201)

      const mismatchedRetry = await completeMcpHandoffResponse(
        request(handoff.flowId, token, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            secretId: SECOND_SECRET_ID,
            revealAuthorization: revealAuthorizationFromFragment(
              secondEncrypted.encrypted.fragment,
            ),
          }),
        }),
        handoff.flowId,
        runtime,
        nowMs + 5,
      )
      expect(mismatchedRetry.status).toBe(404)

      await expect(
        secrets.getStatus(SECRET_ID, encrypted.ownerCapabilityHash, nowMs + 6),
      ).resolves.toMatchObject({ state: 'AVAILABLE' })
      const proofCount = await db
        .prepare('SELECT COUNT(*) AS count FROM reveal_proofs')
        .first<{ count: number }>()
      expect(proofCount?.count).toBe(0)
    } finally {
      db.close()
    }
  })

  it.each(['revoked', 'expired'] as const)(
    'refuses to complete a reveal handoff for a %s secret',
    async (terminalState) => {
      const db = database()
      try {
        const runtime = context(db)
        const nowMs = Date.now()
        const encrypted = await encryptedShareForCreate('lifecycle protected', undefined)
        const secrets = new D1SecretRepository(db)
        const created = await createSecretResponse(
          new Request('https://onceveil.test/api/secrets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              payload: encrypted.encrypted.payload,
              ownerKeyHash: encrypted.ownerCapabilityHash,
              ...(terminalState === 'expired' ? { ttlMs: 1_000 } : {}),
            }),
          }),
          secrets,
          nowMs,
          () => SECRET_ID,
        )
        expect(created.status).toBe(201)

        const handoff = await createMcpHandoff(runtime, 'reveal', nowMs)
        const token = tokenFrom(await mcpHandoffUrl(runtime, handoff))

        const completionTime = terminalState === 'expired' ? nowMs + 1_000 : nowMs + 2
        if (terminalState === 'revoked') {
          await expect(
            secrets.revoke(SECRET_ID, encrypted.ownerCapabilityHash, nowMs + 1),
          ).resolves.toMatchObject({ kind: 'revoked' })
        }

        const response = await completeMcpHandoffResponse(
          request(handoff.flowId, token, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              secretId: SECRET_ID,
              revealAuthorization: revealAuthorizationFromFragment(encrypted.encrypted.fragment),
            }),
          }),
          handoff.flowId,
          runtime,
          completionTime,
        )
        expect(response.status).toBe(404)

        const row = await db
          .prepare('SELECT state FROM mcp_handoffs WHERE flow_id = ?')
          .bind(handoff.flowId)
          .first<{ state: string }>()
        expect(row?.state).toBe('PENDING')
      } finally {
        db.close()
      }
    },
  )

  it.each(['create', 'reveal'] as const)(
    'rejects oversized %s completion bodies before JSON parsing',
    async (action) => {
      const db = database()
      try {
        const runtime = context(db)
        const nowMs = Date.now()
        const handoff = await createMcpHandoff(runtime, action, nowMs)
        const token = tokenFrom(await mcpHandoffUrl(runtime, handoff))
        const oversized = 'x'.repeat(MAX_MCP_HANDOFF_COMPLETION_BYTES + 1)

        const response = await completeMcpHandoffResponse(
          request(handoff.flowId, token, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: oversized,
          }),
          handoff.flowId,
          runtime,
          nowMs + 1,
        )
        expect(response.status).toBe(413)
        await expect(response.json()).resolves.toEqual({ error: 'payload_too_large' })

        const row = await db
          .prepare('SELECT state FROM mcp_handoffs WHERE flow_id = ?')
          .bind(handoff.flowId)
          .first<{ state: string }>()
        expect(row?.state).toBe('PENDING')
      } finally {
        db.close()
      }
    },
  )

  it('revokes issued browser handoff tokens when the storage key rotates', async () => {
    const db = database()
    try {
      const runtime = context(db)
      const nowMs = Date.now()
      const handoff = await createMcpHandoff(runtime, 'reveal', nowMs)
      const token = tokenFrom(await mcpHandoffUrl(runtime, handoff))

      const beforeRotation = await mcpHandoffInfoResponse(
        request(handoff.flowId, token),
        handoff.flowId,
        runtime,
        nowMs + 1,
      )
      expect(beforeRotation.status).toBe(200)

      if (runtime.mcp.status !== 'enabled') {
        throw new Error('test MCP runtime must be enabled')
      }
      const rotated: OnceveilRequestContext = {
        ...runtime,
        mcp: {
          status: 'enabled',
          authToken: runtime.mcp.authToken,
          publicOrigin: runtime.mcp.publicOrigin,
          storageKey: Uint8Array.from(STORAGE_KEY, (byte) => byte ^ 0xff),
        },
      }
      const afterRotation = await mcpHandoffInfoResponse(
        request(handoff.flowId, token),
        handoff.flowId,
        rotated,
        nowMs + 2,
      )
      expect(afterRotation.status).toBe(404)
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
