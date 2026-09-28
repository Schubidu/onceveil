import { describe, expect, it } from 'vitest'

import { resolveMcpRuntime } from '../src/runtime/mcp-config'

const TOKEN = 't'.repeat(32)
const STORAGE_KEY = 'ab'.repeat(32)

describe('MCP runtime configuration', () => {
  it.each([undefined, '', 'false'])('keeps MCP disabled for %s', (enabled) => {
    expect(resolveMcpRuntime(enabled)).toEqual({ status: 'disabled' })
  })

  it('enables MCP only with auth, storage key and canonical public origin', () => {
    const runtime = resolveMcpRuntime('true', {
      authToken: TOKEN,
      storageKey: STORAGE_KEY,
      publicOrigin: 'https://secrets.example',
    })

    expect(runtime.status).toBe('enabled')
    if (runtime.status === 'enabled') {
      expect(runtime.authToken).toBe(TOKEN)
      expect(Array.from(runtime.storageKey)).toHaveLength(32)
      expect(runtime.publicOrigin).toBe('https://secrets.example')
    }
  })

  it.each([
    {},
    { authToken: 'short', storageKey: STORAGE_KEY, publicOrigin: 'https://secrets.example' },
    { authToken: TOKEN, storageKey: '00', publicOrigin: 'https://secrets.example' },
    { authToken: TOKEN, storageKey: STORAGE_KEY, publicOrigin: 'http://secrets.example' },
    { authToken: TOKEN, storageKey: STORAGE_KEY, publicOrigin: 'https://secrets.example/path' },
  ])('fails closed for incomplete or unsafe enabled configuration %#', (environment) => {
    expect(resolveMcpRuntime('true', environment)).toEqual({ status: 'unavailable' })
  })

  it('allows HTTP only for a loopback development origin', () => {
    expect(
      resolveMcpRuntime('true', {
        authToken: TOKEN,
        storageKey: STORAGE_KEY,
        publicOrigin: 'http://127.0.0.1:3000',
      }),
    ).toMatchObject({
      status: 'enabled',
      publicOrigin: 'http://127.0.0.1:3000',
    })
  })

  it.each(['TRUE', '1', 'yes', ' true'])('fails closed for unknown enable value %s', (enabled) => {
    expect(resolveMcpRuntime(enabled)).toEqual({ status: 'unavailable' })
  })
})
