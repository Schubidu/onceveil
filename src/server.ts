import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

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

    const url = new URL(request.url)
    const policy = secretSurfacePolicy(request)
    const frameAncestor = policy === 'turnstile' ? "'self'" : undefined
    const frameSource =
      policy === 'isolated' && url.pathname.startsWith('/s/') ? "'self'" : undefined
    return withSecretSecurityHeaders(response, policy, frameAncestor, frameSource, url.origin)
  },
})
