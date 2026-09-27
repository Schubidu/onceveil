import { env } from 'cloudflare:workers'

import type { RevealVerificationOriginConfig } from '../core/reveal-verification-origin'

interface OnceveilRevealVerificationEnv {
  REVEAL_APP_ORIGIN?: string
  REVEAL_VERIFICATION_ORIGIN?: string
  REVEAL_PREVIEW_APP_ORIGIN?: string
  REVEAL_PREVIEW_VERIFICATION_ORIGIN?: string
}

export function getRevealVerificationOriginConfig(): RevealVerificationOriginConfig {
  const runtime = env as OnceveilRevealVerificationEnv
  return {
    appOrigin: runtime.REVEAL_APP_ORIGIN,
    verificationOrigin: runtime.REVEAL_VERIFICATION_ORIGIN,
    previewAppOrigin: runtime.REVEAL_PREVIEW_APP_ORIGIN,
    previewVerificationOrigin: runtime.REVEAL_PREVIEW_VERIFICATION_ORIGIN,
  }
}
