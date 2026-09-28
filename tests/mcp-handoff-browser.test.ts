import { describe, expect, it } from 'vitest'

import {
  takeMcpHandoffToken,
  validOnceveilShareUrl,
} from '../src/browser/mcp-handoff'
import { encryptSecret, sharePath } from '../src/browser/secret-crypto'
import { generateSecretId } from '../src/core/secret'

describe('MCP browser handoff boundary', () => {
  it('takes the handoff token from the fragment and immediately removes it from history', () => {
    const token = 'a'.repeat(64)
    const replaced: string[] = []

    expect(
      takeMcpHandoffToken(
        {
          hash: `#v1.${token}`,
          pathname: '/mcp/handoff/0123456789abcdef0123456789abcdef',
          search: '',
        },
        {
          state: null,
          replaceState: (_data, _unused, url) => replaced.push(String(url)),
        },
      ),
    ).toBe(token)

    expect(replaced).toEqual(['/mcp/handoff/0123456789abcdef0123456789abcdef'])
  })

  it('accepts only a complete same-origin Onceveil share URL', async () => {
    const id = generateSecretId()
    const encrypted = await encryptSecret('browser only')
    const path = sharePath(id, encrypted.fragment)
    const url = `https://onceveil.example${path}`

    expect(validOnceveilShareUrl(url, 'https://onceveil.example')).toBe(url)
    expect(validOnceveilShareUrl(url, 'https://other.example')).toBeUndefined()
    expect(
      validOnceveilShareUrl(
        `https://onceveil.example/s/${id}?leak=1#${encrypted.fragment}`,
        'https://onceveil.example',
      ),
    ).toBeUndefined()
  })

  it('rejects malformed handoff and share fragments', () => {
    expect(
      takeMcpHandoffToken(
        { hash: '#v1.short', pathname: '/mcp/handoff/test', search: '' },
        { state: null, replaceState() {} },
      ),
    ).toBeUndefined()

    expect(
      validOnceveilShareUrl(
        'https://onceveil.example/s/0123456789abcdef0123456789abcdef#v2.invalid',
        'https://onceveil.example',
      ),
    ).toBeUndefined()

    expect(
      validOnceveilShareUrl(
        'https://onceveil.example/s/%zz#v2.invalid',
        'https://onceveil.example',
      ),
    ).toBeUndefined()
  })
})
