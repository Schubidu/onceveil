import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import {
  parentOriginForVerification,
  verificationOriginForParent,
} from './core/reveal-verification-origin'
import {
  isSecretSurface,
  secretSurfacePolicy,
  withSecretSecurityHeaders,
} from './runtime/security-headers'
import { getRevealVerificationOriginConfig } from './runtime/reveal-verification-origin'

export default createServerEntry({
  async fetch(request) {
    const response = await handler.fetch(request)
    if (!isSecretSurface(request)) {
      return response
    }

    const url = new URL(request.url)
    const policy = secretSurfacePolicy(request)
    const originConfig = getRevealVerificationOriginConfig()
    const expectedParentOrigin =
      policy === 'turnstile'
        ? parentOriginForVerification(url.origin, originConfig)
        : undefined
    const requestedParentOrigin = url.searchParams.get('parent') ?? undefined
    const frameAncestor =
      expectedParentOrigin && requestedParentOrigin === expectedParentOrigin
        ? expectedParentOrigin
        : undefined
    const frameSource =
      policy === 'isolated' && url.pathname.startsWith('/s/')
        ? verificationOriginForParent(url.origin, originConfig)
        : undefined
    return withSecretSecurityHeaders(response, policy, frameAncestor, frameSource, url.origin)
  },
})
