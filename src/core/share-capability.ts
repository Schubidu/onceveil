import { isValidSecretId, type SecretId } from './secret'

export const SHARE_PROTOCOL_VERSION = 'v1' as const
export const SHARE_AAD_PREFIX = 'onceveil'

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/

export interface EncryptedSecretPayload {
  id: SecretId
  version: typeof SHARE_PROTOCOL_VERSION
  nonce: string
  ciphertext: string
}

export function isEncryptedSecretPayload(value: unknown): value is EncryptedSecretPayload {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  const candidate = value as Record<string, unknown>
  return (
    candidate.version === SHARE_PROTOCOL_VERSION &&
    typeof candidate.id === 'string' &&
    isValidSecretId(candidate.id) &&
    typeof candidate.nonce === 'string' &&
    candidate.nonce.length > 0 &&
    BASE64URL_PATTERN.test(candidate.nonce) &&
    typeof candidate.ciphertext === 'string' &&
    candidate.ciphertext.length > 0 &&
    BASE64URL_PATTERN.test(candidate.ciphertext)
  )
}

export function encodeEncryptedSecretPayload(payload: EncryptedSecretPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload))
}

export function decodeEncryptedSecretPayload(bytes: Uint8Array): EncryptedSecretPayload | undefined {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return isEncryptedSecretPayload(value) ? value : undefined
  } catch {
    return undefined
  }
}

export function shareAssociatedData(id: SecretId): string {
  return `${SHARE_AAD_PREFIX}:${SHARE_PROTOCOL_VERSION}:${id}`
}
