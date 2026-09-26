import { env } from 'cloudflare:workers'

import { D1RevealProofRepository } from '../adapters/d1-reveal-proof-repository'
import {
  TurnstileRevealChallengeVerifier,
  turnstileRevealProtectionConfiguration,
} from '../adapters/turnstile-reveal-protection'
import type { RevealChallengeVerifier, RevealProofRepository } from '../core/reveal-protection'
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

function turnstileConfiguration() {
  const runtime = revealProtectionEnv()
  const config = turnstileRevealProtectionConfiguration(
    runtime.TURNSTILE_SITE_KEY,
    runtime.TURNSTILE_SECRET_KEY,
  )
  if (!config) {
    throw new RevealProtectionUnavailableError()
  }

  return config
}

export function getTurnstileSiteKey(): string {
  return turnstileConfiguration().siteKey
}

export function getRevealChallengeVerifier(): RevealChallengeVerifier {
  return new TurnstileRevealChallengeVerifier(turnstileConfiguration().secretKey)
}

export function getRevealProofRepository(): RevealProofRepository {
  return new D1RevealProofRepository(getSecretDatabase())
}
