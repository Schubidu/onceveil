import type { OwnerCapabilityHash } from './owner-capability'
import type { SecretId } from './secret'

export const MCP_HANDOFF_TTL_MS = 10 * 60 * 1000

export type McpFlowId = string & { readonly __mcpFlowId: unique symbol }
export type McpHandoffToken = string & { readonly __mcpHandoffToken: unique symbol }
export type McpHandoffAction = 'create' | 'reveal'
export type McpHandoffState = 'PENDING' | 'COMPLETED'

const FLOW_ID_PATTERN = /^[0-9a-f]{32}$/
const HANDOFF_TOKEN_PATTERN = /^[0-9a-f]{64}$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/

export interface SealedMcpValue {
  nonce: string
  ciphertext: string
}

export interface McpHandoffRecord {
  flowId: McpFlowId
  action: McpHandoffAction
  state: McpHandoffState
  handoffTokenHash: string
  handoffToken?: SealedMcpValue
  createdAtMs: number
  handoffExpiresAtMs: number
  completedAtMs?: number
  secretId?: SecretId
  ownerKeyHash?: OwnerCapabilityHash
}

export type CompleteMcpHandoffResult = 'completed' | 'replayed' | 'unavailable'

export interface McpHandoffRepository {
  create(record: McpHandoffRecord): Promise<boolean>
  get(flowId: McpFlowId): Promise<McpHandoffRecord | undefined>
  getAuthorized(
    flowId: McpFlowId,
    handoffTokenHash: string,
    nowMs: number,
  ): Promise<McpHandoffRecord | undefined>
  completeCreate(
    flowId: McpFlowId,
    handoffTokenHash: string,
    secretId: SecretId,
    ownerKeyHash: OwnerCapabilityHash,
    nowMs: number,
  ): Promise<CompleteMcpHandoffResult>
  completeReveal(
    flowId: McpFlowId,
    handoffTokenHash: string,
    secretId: SecretId,
    revealAuthorization: string,
    nowMs: number,
  ): Promise<CompleteMcpHandoffResult>
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function generateMcpFlowId(): McpFlowId {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return hex(bytes) as McpFlowId
}

export function generateMcpHandoffToken(): McpHandoffToken {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return hex(bytes) as McpHandoffToken
}

export function isValidMcpFlowId(value: string): value is McpFlowId {
  return FLOW_ID_PATTERN.test(value)
}

export function isValidMcpHandoffToken(value: string): value is McpHandoffToken {
  return HANDOFF_TOKEN_PATTERN.test(value)
}

export function isValidMcpHash(value: string): boolean {
  return SHA256_PATTERN.test(value)
}
