import type { D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { RuntimeEnvironment } from './readiness'

export type RevealProtectionRuntime =
  | {
      provider: 'turnstile'
      siteKey: string
      secretKey: string
    }
  | {
      provider: 'altcha'
      secretKey: string
    }
  | {
      provider: 'none'
    }
  | {
      provider: 'unavailable'
    }

export type DatabaseEnvironment = RuntimeEnvironment | 'markerless' | 'unavailable'

export interface OnceveilRequestContext {
  secretDatabase?: D1DatabaseLike
  databaseEnvironment: DatabaseEnvironment
  revealProtection: RevealProtectionRuntime
}
