import { describe, expect, it, vi } from 'vitest'

import { D1SecretRepository } from '../src/adapters/d1-secret-repository'
import { NodeSqliteDatabase } from '../src/adapters/node-sqlite-database'
import { applySqliteMigrations } from '../src/adapters/sqlite-migrations'
import { encryptedShareForCreate } from '../src/browser/secret-create-retry'
import { DEFAULT_BRANDING } from '../src/core/branding'
import type { SecretId } from '../src/core/secret'
import { completeMcpHandoffResponse } from '../src/runtime/mcp-handoff-http'
import { createOnceveilMcpHandler } from '../src/runtime/mcp-server'
import type { OnceveilRequestContext } from '../src/runtime/request-context'
import { createSecretResponse } from '../src/runtime/secret-http'

const MODERN = '2026-07-28'
const PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion'
const CLIENT_INFO_META_KEY = 'io.modelcontextprotocol/clientInfo'
const CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities'

const STORAGE_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
const MCP_TOKEN = 'm'.repeat(32)
const SECRET_ID = 'f'.repeat(32) as SecretId
const MODEL_SECRET = 'MODEL_CONTEXT_MUST_NEVER_SEE_THIS_SECRET'

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
      authToken: MCP_TOKEN,
      storageKey: STORAGE_KEY,
      publicOrigin: 'https://onceveil.test',
    },
  }
}

function modernToolCall(
  name: string,
  args: Record<string, unknown> = {},
  extraParams: Record<string, unknown> = {},
): Request {
  const body = {
    jsonrpc: '2.0',
    id: crypto.randomUUID(),
    method: 'tools/call',
    params: {
      name,
      arguments: args,
      ...extraParams,
      _meta: {
        [PROTOCOL_VERSION_META_KEY]: MODERN,
        [CLIENT_INFO_META_KEY]: { name: 'onceveil-security-test', version: '1.0.0' },
        [CLIENT_CAPABILITIES_META_KEY]: { elicitation: { url: {} } },
      },
    },
  }

  return new Request('https://onceveil.test/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': MODERN,
      'Mcp-Method': 'tools/call',
      'Mcp-Name': name,
    },
    body: JSON.stringify(body),
  })
}

async function result(response: Response): Promise<Record<string, unknown>> {
  expect(response.status).toBe(200)
  const body = (await response.json()) as { result?: Record<string, unknown> }
  expect(body.result).toBeDefined()
  return body.result ?? {}
}

function elicitation(resultValue: Record<string, unknown>) {
  const requests = resultValue.inputRequests as
    | Record<string, { params?: { url?: unknown } }>
    | undefined
  const url = requests?.browser?.params?.url
  expect(typeof url).toBe('string')
  return new URL(url as string)
}

function fragmentToken(url: URL): string {
  const match = /^#v1\.([0-9a-f]{64})$/.exec(url.hash)
  expect(match).not.toBeNull()
  return match?.[1] ?? ''
}

describe('MCP model-context boundary', () => {
  it('keeps create capabilities out of model-visible results and manages by flow id only', async () => {
    const db = database()
    const runtime = context(db)
    const handler = await createOnceveilMcpHandler(runtime)
    const spies = [
      vi.spyOn(console, 'log').mockImplementation(() => undefined),
      vi.spyOn(console, 'info').mockImplementation(() => undefined),
      vi.spyOn(console, 'warn').mockImplementation(() => undefined),
      vi.spyOn(console, 'error').mockImplementation(() => undefined),
    ]

    try {
      const first = await result(await handler.fetch(modernToolCall('create_secret_handoff')))
      expect(first.resultType).toBe('input_required')
      expect(first.content).toBeUndefined()
      expect(first.structuredContent).toBeUndefined()

      const handoffUrl = elicitation(first)
      const token = fragmentToken(handoffUrl)
      const flowId = handoffUrl.pathname.split('/').at(-1) ?? ''
      const requestState = first.requestState
      expect(typeof requestState).toBe('string')
      expect(String(requestState)).not.toContain(token)

      const pending = await encryptedShareForCreate(MODEL_SECRET, undefined)
      const nowMs = Date.now()
      const create = await createSecretResponse(
        new Request('https://onceveil.test/api/secrets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            payload: pending.encrypted.payload,
            ownerKeyHash: pending.ownerCapabilityHash,
          }),
        }),
        new D1SecretRepository(db),
        nowMs,
        () => SECRET_ID,
      )
      expect(create.status).toBe(201)

      const shareUrl = `https://onceveil.test/s/${SECRET_ID}#${pending.encrypted.fragment}`
      const ownerUrl = `https://onceveil.test/o/${SECRET_ID}#v1.${pending.ownerCapability}`

      const completed = await completeMcpHandoffResponse(
        new Request(`https://onceveil.test/api/mcp/handoffs/${flowId}`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            secretId: SECRET_ID,
            ownerKeyHash: pending.ownerCapabilityHash,
          }),
        }),
        flowId,
        runtime,
        nowMs + 1,
      )
      expect(completed.status).toBe(200)

      const second = await result(
        await handler.fetch(
          modernToolCall(
            'create_secret_handoff',
            {},
            {
              requestState,
              inputResponses: {
                browser: { action: 'accept' },
              },
            },
          ),
        ),
      )
      expect(second.resultType).toBe('complete')
      expect(second.structuredContent).toMatchObject({
        flowId,
        state: 'AVAILABLE',
      })

      const modelVisible = JSON.stringify({
        content: second.content,
        structuredContent: second.structuredContent,
      })
      for (const sensitive of [
        MODEL_SECRET,
        pending.encrypted.fragment,
        pending.ownerCapability,
        token,
        shareUrl,
        ownerUrl,
      ]) {
        expect(modelVisible).not.toContain(sensitive)
      }

      const status = await result(await handler.fetch(modernToolCall('secret_status', { flowId })))
      expect(status.structuredContent).toMatchObject({
        flowId,
        state: 'AVAILABLE',
      })

      const revoked = await result(await handler.fetch(modernToolCall('revoke_secret', { flowId })))
      expect(revoked.structuredContent).toMatchObject({
        flowId,
        state: 'REVOKED',
      })

      const repository = new D1SecretRepository(db)
      await expect(
        repository.getStatus(SECRET_ID, pending.ownerCapabilityHash, nowMs + 2),
      ).resolves.toMatchObject({ state: 'REVOKED' })

      const storedHandoff = await db
        .prepare(
          'SELECT handoff_token_hash, handoff_token_ciphertext, owner_key_hash FROM mcp_handoffs WHERE flow_id = ?',
        )
        .bind(flowId)
        .first<Record<string, unknown>>()
      const stored = JSON.stringify(storedHandoff)
      expect(stored).not.toContain(token)
      expect(stored).not.toContain(pending.ownerCapability)

      const logged = JSON.stringify(spies.flatMap((spy) => spy.mock.calls))
      for (const sensitive of [
        MODEL_SECRET,
        pending.encrypted.fragment,
        pending.ownerCapability,
        token,
        shareUrl,
        ownerUrl,
      ]) {
        expect(logged).not.toContain(sensitive)
      }
    } finally {
      await handler.close()
      for (const spy of spies) {
        spy.mockRestore()
      }
      db.close()
    }
  })

  it('completes reveal handoff without consuming the secret or bypassing reveal protection', async () => {
    const db = database()
    const runtime = context(db)
    const handler = await createOnceveilMcpHandler(runtime)

    try {
      const pending = await encryptedShareForCreate('still protected', undefined)
      const nowMs = Date.now()
      const secrets = new D1SecretRepository(db)
      const create = await createSecretResponse(
        new Request('https://onceveil.test/api/secrets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            payload: pending.encrypted.payload,
            ownerKeyHash: pending.ownerCapabilityHash,
          }),
        }),
        secrets,
        nowMs,
        () => SECRET_ID,
      )
      expect(create.status).toBe(201)

      const first = await result(await handler.fetch(modernToolCall('reveal_secret_handoff')))
      const handoffUrl = elicitation(first)
      const token = fragmentToken(handoffUrl)
      const flowId = handoffUrl.pathname.split('/').at(-1) ?? ''
      const requestState = first.requestState

      const completed = await completeMcpHandoffResponse(
        new Request(`https://onceveil.test/api/mcp/handoffs/${flowId}`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        flowId,
        runtime,
        nowMs + 1,
      )
      expect(completed.status).toBe(200)

      await expect(
        secrets.getStatus(SECRET_ID, pending.ownerCapabilityHash, nowMs + 2),
      ).resolves.toMatchObject({ state: 'AVAILABLE' })

      const proofCount = await db
        .prepare('SELECT COUNT(*) AS count FROM reveal_proofs')
        .first<{ count: number }>()
      expect(proofCount?.count).toBe(0)

      const finalResult = await result(
        await handler.fetch(
          modernToolCall(
            'reveal_secret_handoff',
            {},
            {
              requestState,
              inputResponses: { browser: { action: 'accept' } },
            },
          ),
        ),
      )
      expect(finalResult.structuredContent).toEqual({
        flowId,
        handoff: 'completed',
      })
      expect(JSON.stringify(finalResult)).not.toContain(pending.encrypted.fragment)
    } finally {
      await handler.close()
      db.close()
    }
  })

  it('rejects tampered requestState before it can advance a handoff', async () => {
    const db = database()
    const runtime = context(db)
    const handler = await createOnceveilMcpHandler(runtime)

    try {
      const first = await result(await handler.fetch(modernToolCall('create_secret_handoff')))
      const handoffUrl = elicitation(first)
      const flowId = handoffUrl.pathname.split('/').at(-1) ?? ''
      const requestState = String(first.requestState)
      const macSeparator = requestState.lastIndexOf('.')
      expect(macSeparator).toBeGreaterThan(0)
      const macStart = macSeparator + 1
      const firstMacCharacter = requestState[macStart]
      const tampered =
        requestState.slice(0, macStart) +
        (firstMacCharacter === 'A' ? 'B' : 'A') +
        requestState.slice(macStart + 1)

      const response = await handler.fetch(
        modernToolCall(
          'create_secret_handoff',
          {},
          {
            requestState: tampered,
            inputResponses: { browser: { action: 'accept' } },
          },
        ),
      )
      expect(response.status).toBe(200)
      const rejected = (await response.json()) as {
        error?: { code?: number; message?: string }
      }
      expect(rejected.error).toMatchObject({
        code: -32602,
      })

      const row = await db
        .prepare('SELECT state FROM mcp_handoffs WHERE flow_id = ?')
        .bind(flowId)
        .first<{ state: string }>()
      expect(row?.state).toBe('PENDING')
    } finally {
      await handler.close()
      db.close()
    }
  })
})
