import { describe, expect, it } from 'vitest'

import { nodeRevealProtection } from '../src/runtime/node-request-context'

describe('Node reveal protection configuration', () => {
  it('enables none only when explicitly configured', () => {
    expect(nodeRevealProtection('none')).toEqual({ provider: 'none' })
  })

  it('enables ALTCHA only with an explicit sufficiently long HMAC secret', () => {
    const secret = 'a'.repeat(32)
    expect(nodeRevealProtection('altcha', secret)).toEqual({
      provider: 'altcha',
      hmacSecret: secret,
    })
    expect(nodeRevealProtection('altcha')).toEqual({ provider: 'unavailable' })
    expect(nodeRevealProtection('altcha', 'too-short')).toEqual({ provider: 'unavailable' })
  })

  it.each([undefined, '', 'turnstile', 'NONE', 'none '])('fails closed for %s', (value) => {
    expect(nodeRevealProtection(value)).toEqual({ provider: 'unavailable' })
  })
})
