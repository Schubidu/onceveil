import { describe, expect, it } from 'vitest'

import { nodeRevealProtection } from '../src/runtime/node-request-context'

describe('Node reveal protection configuration', () => {
  it('enables none only when explicitly configured', () => {
    expect(nodeRevealProtection('none')).toEqual({ provider: 'none' })
  })

  it.each([undefined, '', 'turnstile', 'NONE', 'none '])(
    'fails closed for %s',
    (value) => {
      expect(nodeRevealProtection(value)).toEqual({ provider: 'unavailable' })
    },
  )
})
