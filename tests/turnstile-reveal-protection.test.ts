import { describe, expect, it } from 'vitest'

import { TurnstileRevealChallengeVerifier } from '../src/adapters/turnstile-reveal-protection'
import { REVEAL_PROTECTION_ACTION } from '../src/core/reveal-protection'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId

function response(body: unknown, status = 200): Response {
  return Response.json(body, { status })
}

describe('Turnstile reveal challenge verifier', () => {
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
    { success: false, action: REVEAL_PROTECTION_ACTION, hostname: 'ots.schult.dev', cdata: SECRET_ID },
    { success: true, action: 'other', hostname: 'ots.schult.dev', cdata: SECRET_ID },
    { success: true, action: REVEAL_PROTECTION_ACTION, hostname: 'evil.example', cdata: SECRET_ID },
    { success: true, action: REVEAL_PROTECTION_ACTION, hostname: 'ots.schult.dev', cdata: 'other' },
  ])('rejects mismatched verification context %#', async (siteverify) => {
    const verifier = new TurnstileRevealChallengeVerifier(
      'secret-key',
      (async () => response(siteverify)) as typeof fetch,
    )

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })

  it('fails closed when Siteverify is unavailable', async () => {
    const verifier = new TurnstileRevealChallengeVerifier(
      'secret-key',
      (async () => {
        throw new Error('network down')
      }) as typeof fetch,
    )

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toEqual({ kind: 'unavailable' })
  })

  it('fails closed on a non-successful Siteverify HTTP response', async () => {
    const verifier = new TurnstileRevealChallengeVerifier(
      'secret-key',
      (async () => response({}, 503)) as typeof fetch,
    )

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
      }),
    ).resolves.toEqual({ kind: 'unavailable' })
  })
})
