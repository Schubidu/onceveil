import { env } from 'cloudflare:workers'

import { D1RevealProofRepository } from '../adapters/d1-reveal-proof-repository'
import { TurnstileRevealChallengeVerifier } from '../adapters/turnstile-reveal-protection'
import type {
  RevealChallengeVerifier,
  RevealProofRepository,
} from '../core/reveal-protection'
import { getSecretDatabase } from './secret-repository'

interface OnceveilRevealProtectionEnv {
  TURNSTILE_SITE_KEY?: string
  TURNSTILE_SECRET_KEY?: string
}

export class RevealProtectionUnavailableError extends Error {
  constructor() {
    super('Reveal protection is unavailable')
    this.name = 'RevealProtectionUnavailableError'
  }
}

function revealProtectionEnv(): OnceveilRevealProtectionEnv {
  return env as OnceveilRevealProtectionEnv
}

function requiredValue(value: string | undefined): string {
  const normalized = value?.trim()
  if (!normalized) {
    throw new RevealProtectionUnavailableError()
  }

  return normalized
}

export function getTurnstileSiteKey(): string {
  return requiredValue(revealProtectionEnv().TURNSTILE_SITE_KEY)
}

export function getRevealChallengeVerifier(): RevealChallengeVerifier {
  const secretKey = requiredValue(revealProtectionEnv().TURNSTILE_SECRET_KEY)
  return new TurnstileRevealChallengeVerifier(secretKey)
}

export function getRevealProofRepository(): RevealProofRepository {
  return new D1RevealProofRepository(getSecretDatabase())
}
