import handler, { createServerEntry } from '@tanstack/react-start/server-entry'

import { createRequestContext } from '#onceveil-runtime-context'
import { handleMcpRequest } from './runtime/mcp-http'
import {
  isSecretSurface,
  secretSurfacePolicy,
  withSecretSecurityHeaders,
} from './runtime/security-headers'

export default createServerEntry({
  async fetch(request) {
    if (new URL(request.url).pathname === '/mcp') {
      return handleMcpRequest(request)
    }

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
