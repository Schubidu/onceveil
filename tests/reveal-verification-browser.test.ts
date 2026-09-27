import { describe, expect, it } from 'vitest'

import {
  discardRevealVerificationFragment,
  isExpectedVerificationMessage,
  REVEAL_VERIFICATION_WINDOW_FEATURES,
  revealVerificationId,
  revealVerificationUrl,
} from '../src/browser/reveal-verification'
import type { SecretId } from '../src/core/secret'
import {
  parentOriginForVerification,
  verificationOriginForParent,
} from '../src/platform/cloudflare-verification-origin'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId
const VERIFICATION_ID = 'fedcba9876543210fedcba9876543210'

describe('reveal verification browser isolation', () => {
  it('builds a fragment-free verification URL containing only the public verification id', () => {
    const url = new URL(revealVerificationUrl(SECRET_ID, VERIFICATION_ID, 'https://ots.schult.dev'))

    expect(url.pathname).toBe(`/s/${SECRET_ID}`)
    expect(url.searchParams.get('verify')).toBe('turnstile')
    expect(url.searchParams.get('verification')).toBe(VERIFICATION_ID)
    expect(url.searchParams.has('proof')).toBe(false)
    expect(url.hash).toBe('')
  })

  it('discards any fragment before the verification context can load third-party code', () => {
    const replacements: Array<{ state: unknown; url: string | URL | null | undefined }> = []
    const location = {
      hash: '#v1.must-not-reach-turnstile',
      pathname: `/s/${SECRET_ID}`,
      search: `?verify=turnstile&verification=${VERIFICATION_ID}`,
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
        url: `/s/${SECRET_ID}?verify=turnstile&verification=${VERIFICATION_ID}`,
      },
    ])
  })

  it('accepts only the expected window, paired origin and verification id', () => {
    const source = {} as MessageEventSource
    const verificationOrigin = 'https://onceveil.schult.workers.dev'
    const message = {
      origin: verificationOrigin,
      source,
      data: {
        type: 'onceveil-reveal-verification-ready',
        verificationId: VERIFICATION_ID,
      },
    }

    expect(
      isExpectedVerificationMessage(message, source, verificationOrigin, VERIFICATION_ID),
    ).toBe(true)
    expect(
      isExpectedVerificationMessage(
        message,
        {} as MessageEventSource,
        verificationOrigin,
        VERIFICATION_ID,
      ),
    ).toBe(false)
    expect(
      isExpectedVerificationMessage(message, source, 'https://ots.schult.dev', VERIFICATION_ID),
    ).toBe(false)
    expect(isExpectedVerificationMessage(message, source, verificationOrigin, 'a'.repeat(32))).toBe(
      false,
    )
  })

  it('maps production and preview origins to a distinct verifier origin', () => {
    expect(verificationOriginForParent('https://ots.schult.dev')).toBe(
      'https://onceveil.schult.workers.dev',
    )
    expect(parentOriginForVerification('https://onceveil.schult.workers.dev')).toBe(
      'https://ots.schult.dev',
    )

    const previewParent =
      'https://feat-issue-20-embedded-reveal-verification.ots-preview.schult.dev'
    const previewVerifier =
      'https://feat-issue-20-embedded-reveal-verification-onceveil.schult.workers.dev'
    expect(verificationOriginForParent(previewParent)).toBe(previewVerifier)
    expect(parentOriginForVerification(previewVerifier)).toBe(previewParent)
    expect(verificationOriginForParent('http://localhost:3000')).toBeUndefined()
  })

  it('requires an isolated opener-less browsing context', () => {
    expect(REVEAL_VERIFICATION_WINDOW_FEATURES).toContain('noopener')
    expect(REVEAL_VERIFICATION_WINDOW_FEATURES).toContain('noreferrer')
  })

  it('recognizes only valid verification identifiers', () => {
    expect(revealVerificationId(`?verify=turnstile&verification=${VERIFICATION_ID}`)).toBe(
      VERIFICATION_ID,
    )
    expect(revealVerificationId('?verify=turnstile&verification=bad')).toBeUndefined()
    expect(revealVerificationId(`?verification=${VERIFICATION_ID}`)).toBeUndefined()
  })
})
