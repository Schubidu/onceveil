import type { SecretId } from './secret'

export const OWNER_CAPABILITY_VERSION = 'v1' as const
export const OWNER_CAPABILITY_BYTES = 32

const OWNER_CAPABILITY_PATTERN = /^[0-9a-f]{64}$/
const OWNER_CAPABILITY_HASH_PATTERN = /^[0-9a-f]{64}$/

export type OwnerCapability = string & { readonly __ownerCapability: unique symbol }
export type OwnerCapabilityHash = string & { readonly __ownerCapabilityHash: unique symbol }

export interface OwnerCapabilityReference {
  id: SecretId
  capability: OwnerCapability
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function generateOwnerCapability(): OwnerCapability {
  const bytes = new Uint8Array(OWNER_CAPABILITY_BYTES)
  crypto.getRandomValues(bytes)
  return hex(bytes) as OwnerCapability
}

export function isValidOwnerCapability(value: string): value is OwnerCapability {
  return OWNER_CAPABILITY_PATTERN.test(value)
}

export function isValidOwnerCapabilityHash(value: string): value is OwnerCapabilityHash {
  return OWNER_CAPABILITY_HASH_PATTERN.test(value)
}

export async function hashOwnerCapability(
  capability: OwnerCapability,
): Promise<OwnerCapabilityHash> {
  const encoded = new TextEncoder().encode(capability)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoded))
  return hex(digest) as OwnerCapabilityHash
}
