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
} from '../src/core/reveal-verification-origin'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId
const VERIFICATION_ID = 'fedcba9876543210fedcba9876543210'

describe('reveal verification browser isolation', () => {
  it('builds a fragment-free verification URL containing only the public verification id', () => {
    const url = new URL(revealVerificationUrl(SECRET_ID, VERIFICATION_ID, 'https://app.example.com'))

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
    const verificationOrigin = 'https://verify.example.com'
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
      isExpectedVerificationMessage(message, source, 'https://app.example.com', VERIFICATION_ID),
    ).toBe(false)
    expect(isExpectedVerificationMessage(message, source, verificationOrigin, 'a'.repeat(32))).toBe(
      false,
    )
  })

  it('maps configured production and preview origin pairs without deployment-specific domains', () => {
    const config = {
      appOrigin: 'https://app.example.com',
      verificationOrigin: 'https://verify.example.com',
      previewAppOrigin: 'https://preview.example.com',
      previewVerificationOrigin: 'https://verify-preview.example.com',
    }

    expect(verificationOriginForParent('https://app.example.com', config)).toBe(
      'https://verify.example.com',
    )
    expect(parentOriginForVerification('https://verify.example.com', config)).toBe(
      'https://app.example.com',
    )

    const previewParent = 'https://feature-x.preview.example.com'
    const previewVerifier = 'https://feature-x.verify-preview.example.com'
    expect(verificationOriginForParent(previewParent, config)).toBe(previewVerifier)
    expect(parentOriginForVerification(previewVerifier, config)).toBe(previewParent)
    expect(
      verificationOriginForParent('https://app.example.com', {
        appOrigin: 'https://app.example.com',
        verificationOrigin: 'https://app.example.com',
      }),
    ).toBeUndefined()
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
