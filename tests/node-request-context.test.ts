import { describe, expect, it } from 'vitest'

import { resolveRevealProtectionRuntime } from '../src/runtime/reveal-protection-config'

describe('reveal protection provider selection', () => {
  it('maps explicit none mode to the noop provider', () => {
    expect(resolveRevealProtectionRuntime('none')).toEqual({ provider: 'noop' })
  })

  it('enables ALTCHA only with a valid explicit HMAC secret', () => {
    const hmacSecret = 'a'.repeat(32)
    expect(resolveRevealProtectionRuntime('altcha', { altchaSecret: hmacSecret })).toEqual({
      provider: 'altcha',
      hmacSecret,
    })
    expect(resolveRevealProtectionRuntime('altcha', { altchaSecret: 'too-short' })).toEqual({
      provider: 'unavailable',
    })
  })

  it('enables Turnstile only with both configured keys', () => {
    expect(
      resolveRevealProtectionRuntime('turnstile', {
        turnstileSiteKey: 'site-key',
        turnstileSecretKey: 'secret-key',
      }),
    ).toEqual({
      provider: 'turnstile',
      siteKey: 'site-key',
      secretKey: 'secret-key',
    })
    expect(resolveRevealProtectionRuntime('turnstile', { turnstileSiteKey: 'site-key' })).toEqual({
      provider: 'unavailable',
    })
  })

  it.each([undefined, '', 'NONE', 'none ', 'unknown'])('fails closed for mode %s', (value) => {
    expect(resolveRevealProtectionRuntime(value)).toEqual({ provider: 'unavailable' })
  })
})
