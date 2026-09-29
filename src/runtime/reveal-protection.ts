import type { Challenge } from 'altcha-lib'

import { AltchaRevealProtection } from '../adapters/altcha-reveal-protection'
import { D1RevealProofRepository } from '../adapters/d1-reveal-proof-repository'
import { NoopRevealProtection } from '../adapters/noop-reveal-protection'
import { TurnstileRevealProtection } from '../adapters/turnstile-reveal-protection'
import {
  REVEAL_PROTECTION_ACTION,
  type RevealProofRepository,
  type RevealProtectionVerifier,
} from '../core/reveal-protection'
import type { SecretId } from '../core/secret'
import type { OnceveilRequestContext } from './request-context'
import { getSecretDatabase } from './secret-repository'

export class RevealProtectionUnavailableError extends Error {
  constructor() {
    super('Reveal protection is unavailable')
    this.name = 'RevealProtectionUnavailableError'
  }
}

export type RevealProtectionClientConfig =
  | {
      provider: 'turnstile'
      siteKey: string
      action: typeof REVEAL_PROTECTION_ACTION
    }
  | {
      provider: 'altcha'
      challenge: Challenge
    }
  | {
      provider: 'noop'
    }

function configuredProtection(context: OnceveilRequestContext) {
  if (context.revealProtection.provider === 'unavailable') {
    throw new RevealProtectionUnavailableError()
  }

  return context.revealProtection
}

export function assertRevealProtectionAvailable(context: OnceveilRequestContext): void {
  configuredProtection(context)
}

export async function getRevealProtectionClientConfig(
  context: OnceveilRequestContext,
  secretId: SecretId,
  verificationId: string,
): Promise<RevealProtectionClientConfig> {
  const protection = configuredProtection(context)

  if (protection.provider === 'turnstile') {
    return {
      provider: 'turnstile',
      siteKey: protection.siteKey,
      action: REVEAL_PROTECTION_ACTION,
    }
  }

  if (protection.provider === 'altcha') {
    const provider = new AltchaRevealProtection(protection.hmacSecret)
    return {
      provider: 'altcha',
      challenge: await provider.createChallenge(secretId, verificationId),
    }
  }

  return { provider: 'noop' }
}

export function getRevealProtectionVerifier(
  context: OnceveilRequestContext,
): RevealProtectionVerifier {
  const protection = configuredProtection(context)

  if (protection.provider === 'turnstile') {
    return new TurnstileRevealProtection(protection.secretKey)
  }

  if (protection.provider === 'altcha') {
    return new AltchaRevealProtection(protection.hmacSecret)
  }

  return new NoopRevealProtection()
}

export function getRevealProofRepository(context: OnceveilRequestContext): RevealProofRepository {
  return new D1RevealProofRepository(getSecretDatabase(context))
}

