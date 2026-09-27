import { env } from 'cloudflare:workers'

import { parseRuntimeEnvironment, type RuntimeEnvironment } from './readiness'

interface OnceveilRuntimeEnv {
  ONCEVEIL_ENVIRONMENT?: string
}

export function getRuntimeEnvironment(): RuntimeEnvironment | undefined {
  return parseRuntimeEnvironment((env as OnceveilRuntimeEnv).ONCEVEIL_ENVIRONMENT)
}
