import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import { createRequestContext } from '#onceveil-runtime-context'
import {
  isSecretSurface,
  secretSurfacePolicy,
  withSecretSecurityHeaders,
} from './runtime/security-headers'

export default createServerEntry({
  async fetch(request) {
    const response = await handler.fetch(request, {
      context: createRequestContext(request),
    })
    return isSecretSurface(request)
      ? withSecretSecurityHeaders(response, secretSurfacePolicy(request))
      : response
  },
})
