import { describe, expect, it } from 'vitest'

import { nodeRevealProtection } from '../src/runtime/node-request-context'

describe('Node reveal protection configuration', () => {
  it('enables none only when explicitly configured', () => {
    expect(nodeRevealProtection('none')).toEqual({ provider: 'none' })
  })

  it('enables ALTCHA only with a valid explicit HMAC secret', () => {
    const hmacSecret = 'a'.repeat(32)
    expect(nodeRevealProtection('altcha', hmacSecret)).toEqual({
      provider: 'altcha',
      hmacSecret,
    })
    expect(nodeRevealProtection('altcha', 'too-short')).toEqual({ provider: 'unavailable' })
  })

  it.each([undefined, '', 'turnstile', 'altcha', 'NONE', 'none '])(
    'fails closed for %s without valid configuration',
    (value) => {
      expect(nodeRevealProtection(value)).toEqual({ provider: 'unavailable' })
    },
  )
})
