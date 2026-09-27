import { env } from 'cloudflare:workers'

import type { D1DatabaseLike } from '../adapters/d1-secret-repository'
import { runtimeEnvironmentForRequest } from './readiness'
import type { OnceveilRequestContext } from './request-context'

interface CloudflareOnceveilEnv {
  DB?: D1DatabaseLike
  TURNSTILE_SITE_KEY?: string
  TURNSTILE_SECRET_KEY?: string
}

export function createRequestContext(request: Request): OnceveilRequestContext {
  const runtime = env as CloudflareOnceveilEnv
  const siteKey = runtime.TURNSTILE_SITE_KEY?.trim()
  const secretKey = runtime.TURNSTILE_SECRET_KEY?.trim()

  return {
    secretDatabase: runtime.DB,
    expectedDatabaseEnvironment: runtimeEnvironmentForRequest(request),
    revealProtection:
      siteKey && secretKey
        ? {
            provider: 'turnstile',
            siteKey,
            secretKey,
          }
        : { provider: 'unavailable' },
  }
}
