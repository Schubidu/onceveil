import { createFileRoute } from '@tanstack/react-router'

import { createRequestContext } from '#onceveil-runtime-context'
import { completeMcpHandoffResponse, mcpHandoffInfoResponse } from '../runtime/mcp-handoff-http'
import { assertSecretDatabaseEnvironment } from '../runtime/secret-repository'

function unavailable(): Response {
  return Response.json(
    { error: 'service_unavailable' },
    {
      status: 503,
      headers: {
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
      },
    },
  )
}

export const Route = createFileRoute('/api/mcp/handoffs/$flowId')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        const context = createRequestContext(request)
        try {
          await assertSecretDatabaseEnvironment(context)
          return await mcpHandoffInfoResponse(request, params.flowId, context)
        } catch {
          return unavailable()
        }
      },
      POST: async ({ request, params }) => {
        const context = createRequestContext(request)
        try {
          await assertSecretDatabaseEnvironment(context)
          return await completeMcpHandoffResponse(request, params.flowId, context)
        } catch {
          return unavailable()
        }
      },
    },
  },
})
