import type { SecretId } from './secret'

export const SHARE_PROTOCOL_VERSION = 'v1' as const
export const SHARE_AAD_PREFIX = 'onceveil'

export interface EncryptedSecretPayload {
  id: SecretId
  version: typeof SHARE_PROTOCOL_VERSION
  nonce: string
  ciphertext: string
}

export function shareAssociatedData(id: SecretId): string {
  return `${SHARE_AAD_PREFIX}:${SHARE_PROTOCOL_VERSION}:${id}`
}
