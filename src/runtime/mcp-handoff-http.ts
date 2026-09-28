import {
  isValidMcpFlowId,
  isValidMcpHandoffToken,
  type McpFlowId,
} from '../core/mcp-handoff'
import {
  hashOwnerCapability,
  isValidOwnerCapability,
} from '../core/owner-capability'
import { isValidSecretId } from '../core/secret'
import {
  hashMcpHandoffToken,
  mcpOwnerCapabilityAad,
  sealMcpValue,
} from './mcp-crypto'
import { getMcpHandoffRepository } from './mcp-repository'
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

  const hash = await hashMcpHandoffToken(token)
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

  const { secretId, ownerCapability } = body as Record<string, unknown>
  if (
    typeof secretId !== 'string' ||
    !isValidSecretId(secretId) ||
    typeof ownerCapability !== 'string' ||
    !isValidOwnerCapability(ownerCapability)
  ) {
    return json({ error: 'invalid_request' }, 400)
  }

  const ownerKeyHash = await hashOwnerCapability(ownerCapability)
  const status = await getSecretRepository(context).getStatus(secretId, ownerKeyHash, nowMs)
  if (!status) {
    return json({ error: 'not_found' }, 404)
  }

  const sealedOwnerCapability = await sealMcpValue(
    ownerCapability,
    context.mcp.storageKey,
    mcpOwnerCapabilityAad(authorized.record.flowId, secretId),
  )
  const result = await getMcpHandoffRepository(context).completeCreate(
    authorized.record.flowId,
    authorized.tokenHash,
    secretId,
    ownerKeyHash,
    sealedOwnerCapability,
    nowMs,
  )

  return result === 'unavailable'
    ? json({ error: 'not_found' }, 404)
    : json({ completed: true }, 200)
}

export function mcpFlowId(value: string): McpFlowId | undefined {
  return isValidMcpFlowId(value) ? value : undefined
}
