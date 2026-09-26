import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import {
  type SecretSurfacePolicy,
  withSecretSecurityHeaders,
} from './runtime/security-headers'

const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/

export function isSecretSurface(request: Request): boolean {
  const pathname = new URL(request.url).pathname
  return (
    pathname === '/' ||
    pathname === '/api/secrets' ||
    pathname.startsWith('/api/secrets/') ||
    pathname.startsWith('/o/') ||
    pathname.startsWith('/s/')
  )
}

export function secretSurfacePolicy(request: Request): SecretSurfacePolicy {
  const url = new URL(request.url)
  const verificationId = url.searchParams.get('verification')
  return url.pathname.startsWith('/s/') &&
    url.searchParams.get('verify') === 'turnstile' &&
    verificationId !== null &&
    VERIFICATION_ID_PATTERN.test(verificationId)
    ? 'turnstile'
    : 'isolated'
}

export default createServerEntry({
  async fetch(request) {
    const response = await handler.fetch(request)
    return isSecretSurface(request)
      ? withSecretSecurityHeaders(response, secretSurfacePolicy(request))
      : response
  },
})
