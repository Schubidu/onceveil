import { isValidMcpFlowId, isValidMcpHandoffToken, type McpFlowId } from '../core/mcp-handoff'
import { isValidOwnerCapabilityHash } from '../core/owner-capability'
import { isValidRevealAuthorization } from '../core/share-capability'
import { isValidSecretId } from '../core/secret'
import { hashMcpHandoffToken } from './mcp-crypto'
import { getMcpHandoffRepository } from './mcp-repository'
import { matchesRevealAuthorization } from './reveal-protection'
import type { OnceveilRequestContext } from './request-context'
import { getSecretRepository } from './secret-repository'

function json(data: unknown, status: number): Response {
  return Response.json(data, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}

function bearerToken(request: Request): string | undefined {
  const authorization = request.headers.get('Authorization')
  if (!authorization?.startsWith('Bearer ')) {
    return undefined
  }

  const token = authorization.slice('Bearer '.length)
  return isValidMcpHandoffToken(token) ? token : undefined
}

async function authorizedHandoff(
  request: Request,
  flowId: string,
  context: OnceveilRequestContext,
  nowMs: number,
) {
  if (!isValidMcpFlowId(flowId) || context.mcp.status !== 'enabled') {
    return undefined
  }

  const token = bearerToken(request)
  if (!token) {
    return undefined
  }

  const hash = await hashMcpHandoffToken(token, context.mcp.storageKey)
  const record = await getMcpHandoffRepository(context).getAuthorized(flowId, hash, nowMs)
  return record ? { tokenHash: hash, record } : undefined
}

export async function mcpHandoffInfoResponse(
  request: Request,
  flowId: string,
  context: OnceveilRequestContext,
  nowMs = Date.now(),
): Promise<Response> {
  const authorized = await authorizedHandoff(request, flowId, context, nowMs)
  if (!authorized) {
    return json({ error: 'not_found' }, 404)
  }
  if (authorized.record.state !== 'PENDING') {
    return json({ error: 'completed' }, 410)
  }

  return json(
    {
      action: authorized.record.action,
      expiresAtMs: authorized.record.handoffExpiresAtMs,
    },
    200,
  )
}

export async function completeMcpHandoffResponse(
  request: Request,
  flowId: string,
  context: OnceveilRequestContext,
  nowMs = Date.now(),
): Promise<Response> {
  if (!Number.isSafeInteger(nowMs)) {
    return json({ error: 'not_found' }, 404)
  }

  const authorized = await authorizedHandoff(request, flowId, context, nowMs)
  if (!authorized || context.mcp.status !== 'enabled') {
    return json({ error: 'not_found' }, 404)
  }

  if (authorized.record.action === 'reveal') {
    let body: unknown
    try {
      body = await request.json()
    } catch {
      return json({ error: 'invalid_request' }, 400)
    }

    if (typeof body !== 'object' || body === null) {
      return json({ error: 'invalid_request' }, 400)
    }

    const { secretId, revealAuthorization } = body as Record<string, unknown>
    if (
      typeof secretId !== 'string' ||
      !isValidSecretId(secretId) ||
      typeof revealAuthorization !== 'string' ||
      !isValidRevealAuthorization(revealAuthorization)
    ) {
      return json({ error: 'invalid_request' }, 400)
    }

    if (!(await matchesRevealAuthorization(context, secretId, revealAuthorization))) {
      return json({ error: 'not_found' }, 404)
    }

    const result = await getMcpHandoffRepository(context).completeReveal(
      authorized.record.flowId,
      authorized.tokenHash,
      nowMs,
    )
    return result === 'unavailable'
      ? json({ error: 'not_found' }, 404)
      : json({ completed: true }, 200)
  }

  let body: unknown
  try {
    body = await request.json()
  } catch {
    return json({ error: 'invalid_request' }, 400)
  }

  if (typeof body !== 'object' || body === null) {
    return json({ error: 'invalid_request' }, 400)
  }

  const { secretId, ownerKeyHash } = body as Record<string, unknown>
  if (
    typeof secretId !== 'string' ||
    !isValidSecretId(secretId) ||
    typeof ownerKeyHash !== 'string' ||
    !isValidOwnerCapabilityHash(ownerKeyHash)
  ) {
    return json({ error: 'invalid_request' }, 400)
  }
  const status = await getSecretRepository(context).getStatus(secretId, ownerKeyHash, nowMs)
  if (!status) {
    return json({ error: 'not_found' }, 404)
  }

  const result = await getMcpHandoffRepository(context).completeCreate(
    authorized.record.flowId,
    authorized.tokenHash,
    secretId,
    ownerKeyHash,
    nowMs,
  )

  return result === 'unavailable'
    ? json({ error: 'not_found' }, 404)
    : json({ completed: true }, 200)
}

export function mcpFlowId(value: string): McpFlowId | undefined {
  return isValidMcpFlowId(value) ? value : undefined
}
