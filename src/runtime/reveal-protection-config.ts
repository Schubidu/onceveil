import { altchaRevealProtectionConfiguration } from '../adapters/altcha-reveal-protection'
import { turnstileRevealProtectionConfiguration } from '../adapters/turnstile-reveal-protection'
import type { RevealProtectionRuntime } from './request-context'

export interface RevealProtectionEnvironment {
  altchaSecret?: string
  turnstileSiteKey?: string
  turnstileSecretKey?: string
}

export function resolveRevealProtectionRuntime(
  value: string | undefined,
  environment: RevealProtectionEnvironment = {},
): RevealProtectionRuntime {
  if (value === 'none') {
    return { provider: 'noop' }
  }

  if (value === 'turnstile') {
    const configuration = turnstileRevealProtectionConfiguration(
      environment.turnstileSiteKey,
      environment.turnstileSecretKey,
    )
    return configuration ? { provider: 'turnstile', ...configuration } : { provider: 'unavailable' }
  }

  if (value === 'altcha') {
    const configuration = altchaRevealProtectionConfiguration(environment.altchaSecret)
    return configuration ? { provider: 'altcha', ...configuration } : { provider: 'unavailable' }
  }

  return { provider: 'unavailable' }
}
