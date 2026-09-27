import { D1RevealProofRepository } from '../adapters/d1-reveal-proof-repository'
import {
  TurnstileRevealChallengeVerifier,
  type TurnstileRevealProtectionConfiguration,
} from '../adapters/turnstile-reveal-protection'
import type { RevealChallengeVerifier, RevealProofRepository } from '../core/reveal-protection'
import type { OnceveilRequestContext } from './request-context'
import { getSecretDatabase } from './secret-repository'

export class RevealProtectionUnavailableError extends Error {
  constructor() {
    super('Reveal protection is unavailable')
    this.name = 'RevealProtectionUnavailableError'
  }
}

function configuredProtection(context: OnceveilRequestContext) {
  if (context.revealProtection.provider === 'unavailable') {
    throw new RevealProtectionUnavailableError()
  }

  return context.revealProtection
}

function turnstileConfiguration(
  context: OnceveilRequestContext,
): TurnstileRevealProtectionConfiguration {
  const protection = configuredProtection(context)
  if (protection.provider !== 'turnstile') {
    throw new RevealProtectionUnavailableError()
  }

  return protection
}

export function getRevealProtectionProvider(context: OnceveilRequestContext): 'turnstile' | 'none' {
  return configuredProtection(context).provider
}

export function getTurnstileSiteKey(context: OnceveilRequestContext): string {
  return turnstileConfiguration(context).siteKey
}

export function getRevealChallengeVerifier(
  context: OnceveilRequestContext,
): RevealChallengeVerifier {
  return new TurnstileRevealChallengeVerifier(turnstileConfiguration(context).secretKey)
}

export function getRevealProofRepository(context: OnceveilRequestContext): RevealProofRepository {
  return new D1RevealProofRepository(getSecretDatabase(context))
}
