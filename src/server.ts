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

    const url = new URL(request.url)
    const policy = secretSurfacePolicy(request)
    const pairedOrigin = pairedCloudflareVerificationOrigin(url.origin)
    const frameAncestor = policy === 'turnstile' ? pairedOrigin : undefined
    const frameSource =
      policy === 'isolated' && url.pathname.startsWith('/s/') ? pairedOrigin : undefined
    return withSecretSecurityHeaders(response, policy, frameAncestor, frameSource)
  },
})
