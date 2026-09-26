import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import {
  isSecretSurface,
  secretSurfacePolicy,
  withSecretSecurityHeaders,
} from './runtime/security-headers'

export default createServerEntry({
  async fetch(request) {
    const response = await handler.fetch(request)
    return isSecretSurface(request)
      ? withSecretSecurityHeaders(response, secretSurfacePolicy(request))
      : response
  },
})
