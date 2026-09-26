import { describe, expect, it } from 'vitest'

import {
  decryptSecret,
  encryptSecret,
  InvalidShareCapabilityError,
  takeShareFragment,
} from '../src/browser/secret-crypto'
import { SHARE_PROTOCOL_VERSION, type EncryptedSecretPayload } from '../src/core/share-capability'
import { generateSecretId } from '../src/core/secret'

function alterBase64Url(value: string): string {
  const replacement = value[0] === 'A' ? 'B' : 'A'
  return replacement + value.slice(1)
}

describe('browser secret crypto', () => {
  it('round-trips plaintext with AES-GCM', async () => {
    const encrypted = await encryptSecret('correct horse battery staple')

    expect(encrypted.payload.version).toBe(SHARE_PROTOCOL_VERSION)
    expect(encrypted.path).toBe(`/s/${encrypted.payload.id}#${encrypted.fragment}`)
    await expect(decryptSecret(encrypted.payload, encrypted.fragment)).resolves.toBe(
      'correct horse battery staple',
    )
  })

  it('keeps key material out of the server-visible payload', async () => {
    const encrypted = await encryptSecret('server must only see ciphertext')

    expect(Object.keys(encrypted.payload).sort()).toEqual(['ciphertext', 'id', 'nonce', 'version'])
    expect('fragment' in encrypted.payload).toBe(false)
    expect('key' in encrypted.payload).toBe(false)
  })

  it('rejects modified ciphertext', async () => {
    const encrypted = await encryptSecret('tamper resistant')
    const tampered: EncryptedSecretPayload = {
      ...encrypted.payload,
      ciphertext: alterBase64Url(encrypted.payload.ciphertext),
    }

    await expect(decryptSecret(tampered, encrypted.fragment)).rejects.toBeInstanceOf(
      InvalidShareCapabilityError,
    )
  })

  it('rejects a modified nonce', async () => {
    const first = await encryptSecret('nonce bound')
    const second = await encryptSecret('different nonce')
    const tampered: EncryptedSecretPayload = {
      ...first.payload,
      nonce: second.payload.nonce,
    }

    await expect(decryptSecret(tampered, first.fragment)).rejects.toBeInstanceOf(
      InvalidShareCapabilityError,
    )
  })

  it('rejects a different secret identifier because it changes AAD', async () => {
    const encrypted = await encryptSecret('aad bound')
    const tampered: EncryptedSecretPayload = {
      ...encrypted.payload,
      id: generateSecretId(),
    }

    await expect(decryptSecret(tampered, encrypted.fragment)).rejects.toBeInstanceOf(
      InvalidShareCapabilityError,
    )
  })

  it('preserves a leading UTF-8 BOM during round-trip', async () => {
    const plaintext = '\ufeffstarts with bom'
    const encrypted = await encryptSecret(plaintext)

    await expect(decryptSecret(encrypted.payload, encrypted.fragment)).resolves.toBe(plaintext)
  })

  it('rejects a wrong key', async () => {
    const first = await encryptSecret('wrong key')
    const second = await encryptSecret('other key')

    await expect(decryptSecret(first.payload, second.fragment)).rejects.toBeInstanceOf(
      InvalidShareCapabilityError,
    )
  })

  it.each([
    null,
    {},
    { version: SHARE_PROTOCOL_VERSION },
    { version: SHARE_PROTOCOL_VERSION, id: 123, nonce: 'x', ciphertext: 'y' },
    {
      version: SHARE_PROTOCOL_VERSION,
      id: 'not-a-secret-id',
      nonce: 'x',
      ciphertext: 'y',
    },
  ])('rejects malformed server payloads consistently', async (payload) => {
    const encrypted = await encryptSecret('malformed payload')

    await expect(decryptSecret(payload, encrypted.fragment)).rejects.toBeInstanceOf(
      InvalidShareCapabilityError,
    )
  })

  it('rejects unsupported payload or fragment versions', async () => {
    const encrypted = await encryptSecret('versioned')

    await expect(
      decryptSecret(
        { ...encrypted.payload, version: 'v2' } as unknown as EncryptedSecretPayload,
        encrypted.fragment,
      ),
    ).rejects.toBeInstanceOf(InvalidShareCapabilityError)

    await expect(
      decryptSecret(encrypted.payload, encrypted.fragment.replace(/^v1\./, 'v2.')),
    ).rejects.toBeInstanceOf(InvalidShareCapabilityError)
  })

  it('moves the fragment into memory and immediately removes it from the URL', () => {
    const replacements: Array<{ state: unknown; url: string | URL | null | undefined }> = []
    const location = {
      hash: '#v1.secret-key-material',
      pathname: '/s/abc123',
      search: '?ignored=1',
    }
    const history = {
      state: { route: 'secret' },
      replaceState(state: unknown, _unused: string, url?: string | URL | null) {
        replacements.push({ state, url })
      },
    }

    expect(takeShareFragment(location, history)).toBe('v1.secret-key-material')
    expect(replacements).toEqual([
      {
        state: history.state,
        url: '/s/abc123?ignored=1',
      },
    ])
  })
})
