import type { D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { BrandingConfig } from '../core/branding'
import type { RuntimeEnvironment } from './readiness'

export type RevealProtectionRuntime =
  | {
      provider: 'turnstile'
      siteKey: string
      secretKey: string
    }
  | {
      provider: 'altcha'
      hmacSecret: string
    }
  | {
      provider: 'noop'
    }
  | {
      provider: 'unavailable'
    }

export type DatabaseEnvironment = RuntimeEnvironment | 'markerless' | 'unavailable'

export interface OnceveilRequestContext {
  branding: BrandingConfig
  secretDatabase?: D1DatabaseLike
  databaseEnvironment: DatabaseEnvironment
  revealProtection: RevealProtectionRuntime
}
