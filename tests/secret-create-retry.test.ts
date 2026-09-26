import { describe, expect, it, vi } from 'vitest'

import { encryptedShareForCreate } from '../src/browser/secret-create-retry'
import type { EncryptedShare } from '../src/browser/secret-crypto'
import type { SecretId } from '../src/core/secret'

function encrypted(label: string): EncryptedShare {
  return {
    payload: {
      contextId: '0123456789abcdef0123456789abcdef' as SecretId,
      version: 'v1',
      nonce: 'AAAAAAAAAAAAAAAA',
      ciphertext: 'AAAAAAAAAAAAAAAAAAAAAA',
    },
    fragment: `v1.${label}.${'a'.repeat(64)}`,
  }
}

describe('create retry encryption', () => {
  it('reuses the same encrypted payload and fragment for an unchanged retry', async () => {
    const encrypt = vi.fn(async (secret: string) => encrypted(secret))

    const first = await encryptedShareForCreate('same secret', undefined, encrypt)
    const retry = await encryptedShareForCreate('same secret', first, encrypt)

    expect(retry).toBe(first)
    expect(retry.encrypted).toBe(first.encrypted)
    expect(encrypt).toHaveBeenCalledTimes(1)
  })

  it('encrypts again after the plaintext changes', async () => {
    const encrypt = vi.fn(async (secret: string) => encrypted(secret))
    const first = await encryptedShareForCreate('first', undefined, encrypt)

    const changed = await encryptedShareForCreate('changed', first, encrypt)

    expect(changed).not.toBe(first)
    expect(changed.secret).toBe('changed')
    expect(encrypt).toHaveBeenCalledTimes(2)
  })
})
