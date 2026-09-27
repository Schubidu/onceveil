import type { D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { RuntimeEnvironment } from './readiness'

export type RevealProtectionRuntime =
  | {
      provider: 'turnstile'
      siteKey: string
      secretKey: string
    }
  | {
      provider: 'none'
    }
  | {
      provider: 'unavailable'
    }

export interface OnceveilRequestContext {
  secretDatabase?: D1DatabaseLike
  expectedDatabaseEnvironment?: RuntimeEnvironment
  revealProtection: RevealProtectionRuntime
}

declare module '@tanstack/react-router' {
  interface Register {
    server: {
      requestContext: OnceveilRequestContext
    }
  }
}
