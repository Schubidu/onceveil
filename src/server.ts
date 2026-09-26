import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import { withSecretSecurityHeaders } from './runtime/security-headers'

function isSecretSurface(request: Request): boolean {
  const pathname = new URL(request.url).pathname
  return (
    pathname === '/api/secrets' ||
    pathname.startsWith('/api/secrets/') ||
    pathname.startsWith('/s/')
  )
}

export default createServerEntry({
  async fetch(request) {
    const response = await handler.fetch(request)
    return isSecretSurface(request) ? withSecretSecurityHeaders(response) : response
  },
})
