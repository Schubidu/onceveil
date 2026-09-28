import { describe, expect, it } from 'vitest'

import {
  deriveMcpRequestStateKey,
  hashMcpHandoffToken,
  openMcpValue,
  sealMcpValue,
} from '../src/runtime/mcp-crypto'

const KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1)

describe('MCP capability protection', () => {
  it('seals a capability without retaining plaintext and binds its purpose', async () => {
    const plaintext = 'a'.repeat(64)
    const sealed = await sealMcpValue(plaintext, KEY, 'flow:create')

    expect(sealed.nonce).not.toContain(plaintext)
    expect(sealed.ciphertext).not.toContain(plaintext)
    await expect(openMcpValue(sealed, KEY, 'flow:create')).resolves.toBe(plaintext)
    await expect(openMcpValue(sealed, KEY, 'flow:reveal')).rejects.toThrow(
      'invalid_mcp_sealed_value',
    )
  })

  it('derives a stable request-state key distinct from the storage key', async () => {
    const first = await deriveMcpRequestStateKey(KEY)
    const second = await deriveMcpRequestStateKey(KEY)

    expect(first).toEqual(second)
    expect(first).not.toEqual(KEY)
    expect(first).toHaveLength(32)
  })

  it('hashes handoff tokens without echoing them', async () => {
    const token = 'b'.repeat(64)
    const hash = await hashMcpHandoffToken(token)

    expect(hash).toMatch(/^[0-9a-f]{64}$/)
    expect(hash).not.toBe(token)
  })
})
