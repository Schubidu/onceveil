import {
  AltchaRevealProtection,
  type AltchaRevealProtectionConfiguration,
} from '../adapters/altcha-reveal-protection'
import { D1RevealProofRepository } from '../adapters/d1-reveal-proof-repository'
import {
  TurnstileRevealChallengeVerifier,
  type TurnstileRevealProtectionConfiguration,
} from '../adapters/turnstile-reveal-protection'
import type { RevealChallengeVerifier, RevealProofRepository } from '../core/reveal-protection'
import type { SecretId } from '../core/secret'
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

function altchaConfiguration(context: OnceveilRequestContext): AltchaRevealProtectionConfiguration {
  const protection = configuredProtection(context)
  if (protection.provider !== 'altcha') {
    throw new RevealProtectionUnavailableError()
  }

  return protection
}

export function getRevealProtectionProvider(
  context: OnceveilRequestContext,
): 'turnstile' | 'altcha' | 'none' {
  return configuredProtection(context).provider
}

export function getTurnstileSiteKey(context: OnceveilRequestContext): string {
  return turnstileConfiguration(context).siteKey
}

export async function createAltchaRevealChallenge(
  context: OnceveilRequestContext,
  secretId: SecretId,
  verificationId: string,
) {
  const protection = new AltchaRevealProtection(altchaConfiguration(context).hmacSecret)
  return protection.createChallenge(secretId, verificationId)
}

export function getRevealChallengeVerifier(
  context: OnceveilRequestContext,
): RevealChallengeVerifier {
  const protection = configuredProtection(context)

  if (protection.provider === 'turnstile') {
    return new TurnstileRevealChallengeVerifier(protection.secretKey)
  }

  if (protection.provider === 'altcha') {
    return new AltchaRevealProtection(protection.hmacSecret)
  }

  throw new RevealProtectionUnavailableError()
}

export function getRevealProofRepository(context: OnceveilRequestContext): RevealProofRepository {
  return new D1RevealProofRepository(getSecretDatabase(context))
}
