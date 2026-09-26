import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import { pairedCloudflareVerificationOrigin } from './platform/cloudflare-verification-origin'
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

    const policy = secretSurfacePolicy(request)
    const frameAncestor =
      policy === 'turnstile'
        ? pairedCloudflareVerificationOrigin(new URL(request.url).origin)
        : undefined
    return withSecretSecurityHeaders(response, policy, frameAncestor)
  },
})
