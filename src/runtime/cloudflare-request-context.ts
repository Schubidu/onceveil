import { env } from 'cloudflare:workers'

import type { D1DatabaseLike } from '../adapters/d1-secret-repository'
import { requiredRuntimeEnvironmentForRequest } from './readiness'
import type { OnceveilRequestContext } from './request-context'
import { resolveRevealProtectionRuntime } from './reveal-protection-config'

interface CloudflareOnceveilEnv {
  DB?: D1DatabaseLike
  ONCEVEIL_REVEAL_PROTECTION?: string
  ONCEVEIL_ALTCHA_SECRET?: string
  TURNSTILE_SITE_KEY?: string
  TURNSTILE_SECRET_KEY?: string
}

export function createRequestContext(request: Request): OnceveilRequestContext {
  const runtime = env as CloudflareOnceveilEnv
  const databaseEnvironment = requiredRuntimeEnvironmentForRequest(request)
  const revealProtection =
    databaseEnvironment === 'unavailable'
      ? { provider: 'unavailable' as const }
      : resolveRevealProtectionRuntime(runtime.ONCEVEIL_REVEAL_PROTECTION, {
          altchaSecret: runtime.ONCEVEIL_ALTCHA_SECRET,
          turnstileSiteKey: runtime.TURNSTILE_SITE_KEY,
          turnstileSecretKey: runtime.TURNSTILE_SECRET_KEY,
        })

  return {
    secretDatabase: runtime.DB,
    databaseEnvironment,
    revealProtection,
  }
}
