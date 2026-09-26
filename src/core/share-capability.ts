import { isValidSecretId, type SecretId } from './secret'

export const SHARE_PROTOCOL_VERSION = 'v1' as const
export const SHARE_AAD_PREFIX = 'onceveil'

const AES_GCM_NONCE_BYTES = 12
const AES_GCM_TAG_BYTES = 16
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/

export interface EncryptedSecretPayload {
  contextId: SecretId
  version: typeof SHARE_PROTOCOL_VERSION
  nonce: string
  ciphertext: string
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodeBase64Url(value: string): Uint8Array | undefined {
  if (value.length === 0 || !BASE64URL_PATTERN.test(value)) {
    return undefined
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')

  try {
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index)
    }

    return encodeBase64Url(bytes) === value ? bytes : undefined
  } catch {
    return undefined
  }
}

function canonicalPayload(value: unknown): EncryptedSecretPayload | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined
  }

  const candidate = value as Record<string, unknown>
  if (
    candidate.version !== SHARE_PROTOCOL_VERSION ||
    typeof candidate.contextId !== 'string' ||
    !isValidSecretId(candidate.contextId) ||
    typeof candidate.nonce !== 'string' ||
    typeof candidate.ciphertext !== 'string'
  ) {
    return undefined
  }

  const nonce = decodeBase64Url(candidate.nonce)
  const ciphertext = decodeBase64Url(candidate.ciphertext)
  if (
    nonce?.byteLength !== AES_GCM_NONCE_BYTES ||
    !ciphertext ||
    ciphertext.byteLength < AES_GCM_TAG_BYTES
  ) {
    return undefined
  }

  return {
    contextId: candidate.contextId,
    version: SHARE_PROTOCOL_VERSION,
    nonce: candidate.nonce,
    ciphertext: candidate.ciphertext,
  }
}

export function isEncryptedSecretPayload(value: unknown): value is EncryptedSecretPayload {
  return canonicalPayload(value) !== undefined
}

export function encodeEncryptedSecretPayload(payload: EncryptedSecretPayload): Uint8Array {
  const canonical = canonicalPayload(payload)
  if (!canonical) {
    throw new TypeError('Invalid encrypted secret payload')
  }

  return new TextEncoder().encode(JSON.stringify(canonical))
}

export async function encryptedPayloadReplayKey(
  payload: EncryptedSecretPayload,
): Promise<string> {
  const encoded = encodeEncryptedSecretPayload(payload)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoded))
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function decodeEncryptedSecretPayload(
  bytes: Uint8Array,
): EncryptedSecretPayload | undefined {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return canonicalPayload(value)
  } catch {
    return undefined
  }
}

export function shareAssociatedData(contextId: SecretId): string {
  return `${SHARE_AAD_PREFIX}:${SHARE_PROTOCOL_VERSION}:${contextId}`
}
