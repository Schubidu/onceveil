import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import { logRuntimeError, logRuntimeWarning } from '../src/runtime/safe-log'
import {
  isSecretSurface,
  secretSecurityHeaders,
  secretSurfacePolicy,
} from '../src/runtime/security-headers'

const SECRET_ID = '0123456789abcdef0123456789abcdef'

describe('sensitive browser security policy', () => {
  it.each([
    'https://onceveil.test/',
    'https://onceveil.test/api/secrets',
    `https://onceveil.test/api/secrets/${SECRET_ID}/reveal`,
    `https://onceveil.test/o/${SECRET_ID}`,
    `https://onceveil.test/s/${SECRET_ID}`,
  ])('protects %s as a sensitive surface', (url) => {
    expect(isSecretSurface(new Request(url))).toBe(true)
  })

  it('keeps ordinary create/share/owner surfaces isolated from third parties', () => {
    const headers = secretSecurityHeaders('isolated')
    const csp = headers['Content-Security-Policy']

    expect(headers['Cache-Control']).toBe('no-store')
    expect(headers['Referrer-Policy']).toBe('no-referrer')
    expect(headers['X-Frame-Options']).toBe('DENY')
    expect(csp).toContain("worker-src 'none'")
    expect(csp).toContain("frame-src 'none'")
    expect(csp).toContain("connect-src 'self'")
    expect(csp).not.toContain('challenges.cloudflare.com')
  })

  it('allows Turnstile only in a valid fragment-free verification context', () => {
    const normal = new Request(`https://onceveil.test/s/${SECRET_ID}`)
    const malformed = new Request(
      `https://onceveil.test/s/${SECRET_ID}?verify=turnstile&verification=bad`,
    )
    const verification = new Request(
      `https://onceveil.test/s/${SECRET_ID}?verify=turnstile&verification=${'a'.repeat(32)}`,
    )

    expect(secretSurfacePolicy(normal)).toBe('isolated')
    expect(secretSurfacePolicy(malformed)).toBe('isolated')
    expect(secretSurfacePolicy(verification)).toBe('turnstile')

    const frameAncestor = 'https://feat-issue-20.ots-preview.schult.dev'
    const headers = secretSecurityHeaders('turnstile', frameAncestor)
    const csp = headers['Content-Security-Policy']
    expect(csp).toContain('script-src')
    expect(csp).toContain('https://challenges.cloudflare.com')
    expect(csp).toContain('frame-src https://challenges.cloudflare.com')
    expect(csp).toContain(`frame-ancestors ${frameAncestor}`)
    expect(headers['Cross-Origin-Resource-Policy']).toBe('cross-origin')
    expect(headers['X-Frame-Options']).toBeUndefined()
  })
})

describe('safe runtime logging', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it.each([
    'src/routes/api.secrets.ts',
    'src/routes/api.secrets.$id.owner.ts',
    'src/routes/api.secrets.$id.reveal.ts',
    'src/adapters/turnstile-reveal-protection.ts',
  ])('%s cannot bypass the safe logging boundary', async (sourcePath) => {
    const source = await readFile(path.resolve(sourcePath), 'utf8')

    expect(source).not.toContain('console.error(')
    expect(source).not.toContain('console.warn(')
  })

  it('drops sensitive fields and error messages from logs', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const canary = 'SENSITIVE_CANARY_9f47'

    logRuntimeError('operation failed', new Error(canary), {
      authorization: `Bearer ${canary}`,
      body: canary,
      capability: canary,
      ciphertext: canary,
      proof: canary,
      requestBody: canary,
      token: canary,
      url: `https://example.test/#${canary}`,
      stage: 'run',
      actual: `query-error:${canary}`,
    })
    logRuntimeWarning('verification rejected', {
      token: canary,
      secret: canary,
      status: 403,
    })

    const serialized = JSON.stringify([...error.mock.calls, ...warn.mock.calls])
    expect(serialized).not.toContain(canary)
    expect(serialized).not.toContain('authorization')
    expect(serialized).not.toContain('ciphertext')
    expect(serialized).not.toContain('token')
    expect(serialized).not.toContain('query-error')
    expect(serialized).not.toContain('actual')
    expect(serialized).toContain('stage')
    expect(serialized).toContain('403')
  })
})
