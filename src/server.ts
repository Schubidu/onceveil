import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import { createRequestContext } from '#onceveil-runtime-context'
import {
  isSecretSurface,
  secretSurfacePolicy,
  withSecretSecurityHeaders,
} from './runtime/security-headers'

export default createServerEntry({
  async fetch(request) {
    const response = await handler.fetch(request)
    if (!isSecretSurface(request)) {
      return response
    }

    const runtime = createRequestContext(request)
    return withSecretSecurityHeaders(
      response,
      secretSurfacePolicy(request, runtime.revealProtection.provider),
    )
  },
})
