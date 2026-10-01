import {
  generateMcpFlowId,
  generateMcpHandoffToken,
  MCP_HANDOFF_TTL_MS,
  type McpFlowId,
  type McpHandoffAction,
  type McpHandoffRecord,
} from '../core/mcp-handoff'
import type { OwnerCapabilityHash } from '../core/owner-capability'
import type { SecretId, SecretStatus } from '../core/secret'
import { hashMcpHandoffToken, mcpHandoffTokenAad, openMcpValue, sealMcpValue } from './mcp-crypto'
import { getMcpHandoffRepository } from './mcp-repository'
import type { OnceveilRequestContext } from './request-context'
import { getSecretRepository } from './secret-repository'

const CREATE_ATTEMPTS = 4

export class McpUnavailableError extends Error {
  constructor() {
    super('MCP is unavailable')
    this.name = 'McpUnavailableError'
  }
}

function enabledMcp(context: OnceveilRequestContext) {
  if (context.mcp.status !== 'enabled') {
    throw new McpUnavailableError()
  }

  return context.mcp
}

export async function createMcpHandoff(
  context: OnceveilRequestContext,
  action: McpHandoffAction,
  nowMs = Date.now(),
): Promise<McpHandoffRecord> {
  if (!Number.isSafeInteger(nowMs)) {
    throw new McpUnavailableError()
  }

  const mcp = enabledMcp(context)
  const repository = getMcpHandoffRepository(context)

  for (let attempt = 0; attempt < CREATE_ATTEMPTS; attempt += 1) {
    const flowId = generateMcpFlowId()
    const token = generateMcpHandoffToken()
    const record: McpHandoffRecord = {
      flowId,
      action,
      state: 'PENDING',
      handoffTokenHash: await hashMcpHandoffToken(token, mcp.storageKey),
      handoffToken: await sealMcpValue(token, mcp.storageKey, mcpHandoffTokenAad(flowId, action)),
      createdAtMs: nowMs,
      handoffExpiresAtMs: nowMs + MCP_HANDOFF_TTL_MS,
    }

    if (await repository.create(record)) {
      return record
    }
  }

  throw new McpUnavailableError()
}

export async function mcpHandoffUrl(
  context: OnceveilRequestContext,
  record: McpHandoffRecord,
): Promise<string> {
  const mcp = enabledMcp(context)
  if (!record.handoffToken) {
    throw new McpUnavailableError()
  }

  const token = await openMcpValue(
    record.handoffToken,
    mcp.storageKey,
    mcpHandoffTokenAad(record.flowId, record.action),
  )
  const url = new URL(`/mcp/handoff/${record.flowId}`, mcp.publicOrigin)
  url.hash = `v1.${token}`
  return url.toString()
}

export async function getMcpHandoff(
  context: OnceveilRequestContext,
  flowId: McpFlowId,
): Promise<McpHandoffRecord | undefined> {
  enabledMcp(context)
  return getMcpHandoffRepository(context).get(flowId)
}

export async function cancelMcpHandoff(
  context: OnceveilRequestContext,
  flowId: McpFlowId,
): Promise<boolean> {
  enabledMcp(context)
  return getMcpHandoffRepository(context).cancel(flowId)
}

function ownerHashForRecord(
  context: OnceveilRequestContext,
  record: McpHandoffRecord,
): { secretId: SecretId; ownerKeyHash: OwnerCapabilityHash } | undefined {
  enabledMcp(context)
  if (
    record.action !== 'create' ||
    record.state !== 'COMPLETED' ||
    !record.secretId ||
    !record.ownerKeyHash
  ) {
    return undefined
  }

  return {
    secretId: record.secretId,
    ownerKeyHash: record.ownerKeyHash,
  }
}

export async function getMcpManagedSecretStatus(
  context: OnceveilRequestContext,
  record: McpHandoffRecord,
  nowMs = Date.now(),
): Promise<SecretStatus | undefined> {
  const authorization = ownerHashForRecord(context, record)
  if (!authorization) {
    return undefined
  }

  return getSecretRepository(context).getStatus(
    authorization.secretId,
    authorization.ownerKeyHash,
    nowMs,
  )
}

export async function revokeMcpManagedSecret(
  context: OnceveilRequestContext,
  record: McpHandoffRecord,
  nowMs = Date.now(),
): Promise<SecretStatus | undefined> {
  const authorization = ownerHashForRecord(context, record)
  if (!authorization) {
    return undefined
  }

  const repository = getSecretRepository(context)
  const result = await repository.revoke(authorization.secretId, authorization.ownerKeyHash, nowMs)
  if (result.kind === 'not_found') {
    return undefined
  }

  return repository.getStatus(authorization.secretId, authorization.ownerKeyHash, nowMs)
}
