import { describe, expect, it } from 'vitest'

import { resolvePublicOrigin } from '../src/runtime/public-origin'

describe('deployment public origin', () => {
  it('resolves a canonical HTTPS origin independently of MCP enablement', () => {
    expect(resolvePublicOrigin('https://secrets.example')).toBe('https://secrets.example')
  })

  it('allows HTTP only for loopback development origins', () => {
    expect(resolvePublicOrigin('http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000')
    expect(resolvePublicOrigin('http://secrets.example')).toBeUndefined()
  })

  it.each([
    undefined,
    '',
    ' https://secrets.example',
    'https://secrets.example/path',
    'https://secrets.example?query=1',
    'https://secrets.example#fragment',
    'https://user@example.com',
    'https://secrets.example\n.evil.example',
  ])('rejects malformed or non-canonical origin %s', (value) => {
    expect(resolvePublicOrigin(value)).toBeUndefined()
  })
})
