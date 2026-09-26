import {
  SHARE_PROTOCOL_VERSION,
  shareAssociatedData,
  type EncryptedSecretPayload,
} from '../core/share-capability'
import { generateSecretId } from '../core/secret'

const AES_KEY_BYTES = 32
const AES_GCM_NONCE_BYTES = 12
const AES_GCM_TAG_BITS = 128

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export interface EncryptedShare {
  payload: EncryptedSecretPayload
  fragment: string
  path: string
}

export interface FragmentLocation {
  hash: string
  pathname: string
  search: string
}

export interface FragmentHistory {
  state: unknown
  replaceState(data: unknown, unused: string, url?: string | URL | null): void
}

function sharePath(id: EncryptedSecretPayload['id'], fragment: string): string {
  return `/s/${encodeURIComponent(id)}#${fragment}`
}

export class InvalidShareCapabilityError extends Error {
  constructor() {
    super('Invalid or unauthenticated share capability')
    this.name = 'InvalidShareCapabilityError'
  }
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodeBase64Url(value: string): Uint8Array {
  if (value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new InvalidShareCapabilityError()
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')

  try {
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index)
    }

    if (encodeBase64Url(bytes) !== value) {
      throw new InvalidShareCapabilityError()
    }

    return bytes
  } catch (error) {
    if (error instanceof InvalidShareCapabilityError) {
      throw error
    }

    throw new InvalidShareCapabilityError()
  }
}

function encodeFragment(keyBytes: Uint8Array): string {
  return `${SHARE_PROTOCOL_VERSION}.${encodeBase64Url(keyBytes)}`
}

function decodeFragment(fragment: string): Uint8Array {
  const [version, encodedKey, extra] = fragment.split('.')
  if (version !== SHARE_PROTOCOL_VERSION || !encodedKey || extra !== undefined) {
    throw new InvalidShareCapabilityError()
  }

  const keyBytes = decodeBase64Url(encodedKey)
  if (keyBytes.byteLength !== AES_KEY_BYTES) {
    throw new InvalidShareCapabilityError()
  }

  return keyBytes
}

function decodeNonce(encodedNonce: string): Uint8Array {
  const nonce = decodeBase64Url(encodedNonce)
  if (nonce.byteLength !== AES_GCM_NONCE_BYTES) {
    throw new InvalidShareCapabilityError()
  }

  return nonce
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(keyBytes), { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
}

export async function encryptSecret(plaintext: string): Promise<EncryptedShare> {
  const id = generateSecretId()
  const keyBytes = randomBytes(AES_KEY_BYTES)
  const nonce = randomBytes(AES_GCM_NONCE_BYTES)
  const key = await importKey(keyBytes)
  const additionalData = encoder.encode(shareAssociatedData(id))

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(additionalData),
        tagLength: AES_GCM_TAG_BITS,
      },
      key,
      toArrayBuffer(encoder.encode(plaintext)),
    ),
  )

  const fragment = encodeFragment(keyBytes)
  const payload: EncryptedSecretPayload = {
    id,
    version: SHARE_PROTOCOL_VERSION,
    nonce: encodeBase64Url(nonce),
    ciphertext: encodeBase64Url(ciphertext),
  }

  return {
    payload,
    fragment,
    path: sharePath(id, fragment),
  }
}

export async function decryptSecret(
  payload: EncryptedSecretPayload,
  fragment: string,
): Promise<string> {
  if (payload.version !== SHARE_PROTOCOL_VERSION) {
    throw new InvalidShareCapabilityError()
  }

  const keyBytes = decodeFragment(fragment)
  const nonce = decodeNonce(payload.nonce)
  const ciphertext = decodeBase64Url(payload.ciphertext)
  const key = await importKey(keyBytes)
  const additionalData = encoder.encode(shareAssociatedData(payload.id))

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(additionalData),
        tagLength: AES_GCM_TAG_BITS,
      },
      key,
      toArrayBuffer(ciphertext),
    )

    return decoder.decode(plaintext)
  } catch {
    throw new InvalidShareCapabilityError()
  }
}

/**
 * Copies the fragment into page memory, then removes it from the visible URL
 * and browser history entry before returning it to the caller.
 */
export function takeShareFragment(
  location: FragmentLocation,
  history: FragmentHistory,
): string | undefined {
  const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
  if (!fragment) {
    return undefined
  }

  history.replaceState(history.state, '', `${location.pathname}${location.search}`)
  return fragment
}
