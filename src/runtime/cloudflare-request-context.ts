import { env } from 'cloudflare:workers'

import type { D1DatabaseLike } from '../adapters/d1-secret-repository'
import { resolveBrandingConfig } from '../core/branding'
import { resolveMcpRuntime } from './mcp-config'
import { requiredRuntimeEnvironmentForRequest } from './readiness'
import type { OnceveilRequestContext } from './request-context'
import { resolveRevealProtectionRuntime } from './reveal-protection-config'

interface CloudflareOnceveilEnv {
  DB?: D1DatabaseLike
  ONCEVEIL_BRAND_NAME?: string
  ONCEVEIL_BRAND_LOGO?: string
  ONCEVEIL_BRAND_FAVICON?: string
  ONCEVEIL_BRAND_ACCENT?: string
  ONCEVEIL_MCP_ENABLED?: string
  ONCEVEIL_MCP_TOKEN?: string
  ONCEVEIL_MCP_STORAGE_KEY?: string
  ONCEVEIL_MCP_PUBLIC_ORIGIN?: string
  ONCEVEIL_REVEAL_PROTECTION?: string
  ONCEVEIL_ALTCHA_SECRET?: string
  TURNSTILE_SITE_KEY?: string
  TURNSTILE_SECRET_KEY?: string
}

export function getBrandingConfig() {
  const runtime = env as CloudflareOnceveilEnv
  return resolveBrandingConfig({
    name: runtime.ONCEVEIL_BRAND_NAME,
    logo: runtime.ONCEVEIL_BRAND_LOGO,
    favicon: runtime.ONCEVEIL_BRAND_FAVICON,
    accent: runtime.ONCEVEIL_BRAND_ACCENT,
  })
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
    branding: getBrandingConfig(),
    secretDatabase: runtime.DB,
    databaseEnvironment,
    mcp: resolveMcpRuntime(runtime.ONCEVEIL_MCP_ENABLED, {
      authToken: runtime.ONCEVEIL_MCP_TOKEN,
      storageKey: runtime.ONCEVEIL_MCP_STORAGE_KEY,
      publicOrigin: runtime.ONCEVEIL_MCP_PUBLIC_ORIGIN,
    }),
    revealProtection,
  }
}
