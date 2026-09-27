import { describe, expect, it } from 'vitest'

import { nodeRevealProtection } from '../src/runtime/node-request-context'

const ALTCHA_SECRET = 'a'.repeat(64)

describe('Node reveal protection configuration', () => {
  it('enables ALTCHA only with an explicit valid secret', () => {
    expect(nodeRevealProtection('altcha', ALTCHA_SECRET)).toEqual({
      provider: 'altcha',
      secretKey: ALTCHA_SECRET,
    })
  })

  it('enables none only when explicitly configured', () => {
    expect(nodeRevealProtection('none', undefined)).toEqual({ provider: 'none' })
  })

  it.each([
    [undefined, undefined],
    ['', ALTCHA_SECRET],
    ['altcha', undefined],
    ['altcha', 'too-short'],
    ['turnstile', ALTCHA_SECRET],
    ['NONE', ALTCHA_SECRET],
    ['none ', ALTCHA_SECRET],
  ])('fails closed for provider=%s', (provider, secret) => {
    expect(nodeRevealProtection(provider, secret)).toEqual({ provider: 'unavailable' })
  })
})
