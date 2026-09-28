import type { SealedMcpValue } from '../core/mcp-handoff'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })
const HKDF_SALT = encoder.encode('onceveil:mcp:v1')
const AES_GCM_NONCE_BYTES = 12

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('invalid_mcp_sealed_value')
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }

  if (base64Url(bytes) !== value) {
    throw new Error('invalid_mcp_sealed_value')
  }

  return bytes
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function deriveSubkey(storageKey: Uint8Array, info: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toArrayBuffer(storageKey), 'HKDF', false, [
    'deriveBits',
  ])
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBuffer(HKDF_SALT),
      info: toArrayBuffer(encoder.encode(info)),
    },
    key,
    256,
  )
  return new Uint8Array(bits)
}

async function encryptionKey(storageKey: Uint8Array): Promise<CryptoKey> {
  const key = await deriveSubkey(storageKey, 'handoff-encryption')
  return crypto.subtle.importKey('raw', toArrayBuffer(key), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

export async function deriveMcpRequestStateKey(storageKey: Uint8Array): Promise<Uint8Array> {
  return deriveSubkey(storageKey, 'request-state')
}

async function handoffAuthorizationKey(storageKey: Uint8Array): Promise<CryptoKey> {
  const key = await deriveSubkey(storageKey, 'handoff-authorization')
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
}

export async function hashMcpHandoffToken(
  token: string,
  storageKey: Uint8Array,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    'HMAC',
    await handoffAuthorizationKey(storageKey),
    toArrayBuffer(encoder.encode(token)),
  )
  return hex(new Uint8Array(signature))
}

export async function sealMcpValue(
  value: string,
  storageKey: Uint8Array,
  associatedData: string,
): Promise<SealedMcpValue> {
  const nonce = new Uint8Array(AES_GCM_NONCE_BYTES)
  crypto.getRandomValues(nonce)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(encoder.encode(associatedData)),
        tagLength: 128,
      },
      await encryptionKey(storageKey),
      toArrayBuffer(encoder.encode(value)),
    ),
  )

  return {
    nonce: base64Url(nonce),
    ciphertext: base64Url(ciphertext),
  }
}

export async function openMcpValue(
  sealed: SealedMcpValue,
  storageKey: Uint8Array,
  associatedData: string,
): Promise<string> {
  const nonce = fromBase64Url(sealed.nonce)
  const ciphertext = fromBase64Url(sealed.ciphertext)
  if (nonce.byteLength !== AES_GCM_NONCE_BYTES) {
    throw new Error('invalid_mcp_sealed_value')
  }

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(encoder.encode(associatedData)),
        tagLength: 128,
      },
      await encryptionKey(storageKey),
      toArrayBuffer(ciphertext),
    )
    return decoder.decode(plaintext)
  } catch {
    throw new Error('invalid_mcp_sealed_value')
  }
}

export function mcpHandoffTokenAad(flowId: string, action: string): string {
  return `onceveil:mcp:handoff-token:${action}:${flowId}`
}
