import { describe, expect, it } from 'vitest'

import {
  discardRevealVerificationFragment,
  REVEAL_VERIFICATION_WINDOW_FEATURES,
  revealVerificationChannel,
  revealVerificationUrl,
} from '../src/browser/reveal-verification'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId
const CHANNEL = 'fedcba9876543210fedcba9876543210'

describe('reveal verification browser isolation', () => {
  it('builds a fragment-free verification URL', () => {
    const url = new URL(revealVerificationUrl(SECRET_ID, CHANNEL, 'https://ots.schult.dev'))

    expect(url.pathname).toBe(`/s/${SECRET_ID}`)
    expect(url.searchParams.get('verify')).toBe('turnstile')
    expect(url.searchParams.get('channel')).toBe(CHANNEL)
    expect(url.hash).toBe('')
  })

  it('discards any fragment before the verification context can load third-party code', () => {
    const replacements: Array<{ state: unknown; url: string | URL | null | undefined }> = []
    const location = {
      hash: '#v1.must-not-reach-turnstile',
      pathname: `/s/${SECRET_ID}`,
      search: `?verify=turnstile&channel=${CHANNEL}`,
    }
    const history = {
      state: { verification: true },
      replaceState(state: unknown, _unused: string, url?: string | URL | null) {
        replacements.push({ state, url })
      },
    }

    discardRevealVerificationFragment(location, history)

    expect(replacements).toEqual([
      {
        state: history.state,
        url: `/s/${SECRET_ID}?verify=turnstile&channel=${CHANNEL}`,
      },
    ])
  })

  it('requires an isolated opener-less browsing context', () => {
    expect(REVEAL_VERIFICATION_WINDOW_FEATURES).toContain('noopener')
    expect(REVEAL_VERIFICATION_WINDOW_FEATURES).toContain('noreferrer')
  })

  it('recognizes only valid verification channels', () => {
    expect(revealVerificationChannel(`?verify=turnstile&channel=${CHANNEL}`)).toBe(CHANNEL)
    expect(revealVerificationChannel('?verify=turnstile&channel=bad')).toBeUndefined()
    expect(revealVerificationChannel(`?channel=${CHANNEL}`)).toBeUndefined()
  })
})
