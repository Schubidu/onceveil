import { describe, expect, it, vi } from 'vitest'

import { TurnstileRevealChallengeVerifier } from '../src/adapters/turnstile-reveal-protection'
import { REVEAL_PROTECTION_ACTION } from '../src/core/reveal-protection'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId

function response(body: unknown, status = 200): Response {
  return Response.json(body, { status })
}

describe('Turnstile reveal challenge verifier', () => {
  it('accepts only the expected action, hostname and secret-bound cData', async () => {
    const fetchImpl = vi.fn(async () =>
      response({
        success: true,
        action: REVEAL_PROTECTION_ACTION,
        hostname: 'ots.schult.dev',
        cdata: SECRET_ID,
      }),
    )
    const verifier = new TurnstileRevealChallengeVerifier('secret-key', fetchImpl as typeof fetch)

    await expect(
      verifier.verify({
        token: 'turnstile-token',
        secretId: SECRET_ID,
        hostname: 'ots.schult.dev',
        remoteIp: '203.0.113.7',
      }),
    ).resolves.toEqual({ kind: 'verified' })

    expect(fetchImpl).toHaveBeenCalledTimes(1)
    const init = fetchImpl.mock.calls[0]?.[1]
    expect(init?.method).toBe('POST')
    expect(String(init?.body)).toContain('response=turnstile-token')
    expect(String(init?.body)).toContain('remoteip=203.0.113.7')
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
