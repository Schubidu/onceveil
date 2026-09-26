import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  TurnstileRevealChallengeVerifier,
  turnstileRevealProtectionConfiguration,
} from '../src/adapters/turnstile-reveal-protection'
import { REVEAL_PROTECTION_ACTION } from '../src/core/reveal-protection'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId

function response(body: unknown, status = 200): Response {
  return Response.json(body, { status })
}

describe('Turnstile reveal challenge verifier', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })
  it('requires both site and secret keys as one configuration boundary', () => {
    expect(turnstileRevealProtectionConfiguration('site-key', 'secret-key')).toEqual({
      siteKey: 'site-key',
      secretKey: 'secret-key',
    })
    expect(turnstileRevealProtectionConfiguration(undefined, 'secret-key')).toBeUndefined()
    expect(turnstileRevealProtectionConfiguration('site-key', undefined)).toBeUndefined()
    expect(turnstileRevealProtectionConfiguration('   ', 'secret-key')).toBeUndefined()
    expect(turnstileRevealProtectionConfiguration('site-key', '   ')).toBeUndefined()
  })

  it('accepts only the expected action, hostname and secret-bound cData', async () => {
    let capturedInit: RequestInit | undefined
    let calls = 0
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls += 1
      capturedInit = init
      return response({
        success: true,
        action: REVEAL_PROTECTION_ACTION,
        hostname: 'ots.schult.dev',
        cdata: SECRET_ID,
      })
    }) as typeof fetch
    const verifier = new TurnstileRevealChallengeVerifier('secret-key', fetchImpl)

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
        remoteIp: '203.0.113.7',
      }),
    ).resolves.toEqual({ kind: 'verified' })

    expect(calls).toBe(1)
    expect(capturedInit?.method).toBe('POST')
    expect(String(capturedInit?.body)).toContain('response=turnstile-token')
    expect(String(capturedInit?.body)).toContain('remoteip=203.0.113.7')
  })

  it.each([
    {
      success: false,
      action: REVEAL_PROTECTION_ACTION,
      hostname: 'ots.schult.dev',
      cdata: SECRET_ID,
    },
    { success: true, action: 'other', hostname: 'ots.schult.dev', cdata: SECRET_ID },
    { success: true, action: REVEAL_PROTECTION_ACTION, hostname: 'evil.example', cdata: SECRET_ID },
    { success: true, action: REVEAL_PROTECTION_ACTION, hostname: 'ots.schult.dev', cdata: 'other' },
  ])('rejects mismatched verification context %#', async (siteverify) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const verifier = new TurnstileRevealChallengeVerifier('secret-key', (async () =>
      response(siteverify)) as typeof fetch)

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toMatchObject({ kind: 'invalid' })

    expect(warn).toHaveBeenCalledWith(
      'Turnstile Siteverify rejected reveal verification',
      expect.objectContaining({
        success: siteverify.success === true,
        hostnameMatches: expect.any(Boolean),
        actionMatches: expect.any(Boolean),
        cdataMatches: expect.any(Boolean),
        errorCodes: [],
      }),
    )
    expect(JSON.stringify(warn.mock.calls)).not.toContain('turnstile-token')
    expect(JSON.stringify(warn.mock.calls)).not.toContain('secret-key')
  })

  it('fails closed when Siteverify is unavailable', async () => {
    const verifier = new TurnstileRevealChallengeVerifier('secret-key', (async () => {
      throw new Error('network down')
    }) as typeof fetch)

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toEqual({ kind: 'unavailable' })
  })

  it('fails closed on a null Siteverify response', async () => {
    const verifier = new TurnstileRevealChallengeVerifier('secret-key', (async () =>
      response(null)) as typeof fetch)

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toEqual({ kind: 'unavailable' })
  })

  it('fails closed on a non-successful Siteverify HTTP response', async () => {
    const verifier = new TurnstileRevealChallengeVerifier('secret-key', (async () =>
      response({}, 503)) as typeof fetch)

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toEqual({ kind: 'unavailable' })
  })
})
