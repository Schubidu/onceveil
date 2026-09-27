import { createFileRoute } from '@tanstack/react-router'

import { createRequestContext } from '#onceveil-runtime-context'
import { ownerRevokeResponse, ownerStatusResponse } from '../runtime/owner-http'
import type { OnceveilRequestContext } from '../runtime/request-context'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { logRuntimeError } from '../runtime/safe-log'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

function jsonError(error: string, status: number): Response {
  return withSecretSecurityHeaders(Response.json({ error }, { status }))
}

async function withOwnerRepository(
  context: OnceveilRequestContext,
  operation: () => Promise<Response>,
): Promise<Response> {
  try {
    await assertSecretDatabaseEnvironment(context)
    return await operation()
  } catch (error) {
    if (error instanceof SecretDatabaseUnavailableError) {
      return jsonError('service_unavailable', 503)
    }

    if (error instanceof SecretDatabaseEnvironmentError) {
      logRuntimeError('secret database environment check failed', error, {
        expected: error.expected,
        diagnostic: error.actual.startsWith('query-error:')
          ? 'query_error'
          : 'environment_mismatch',
      })
      return jsonError('service_unavailable', 503)
    }

    logRuntimeError('secret owner operation failed', error)
    return jsonError('internal_error', 500)
  }
}

export const Route = createFileRoute('/api/secrets/$id/owner')({
  server: {
    handlers: {
      GET: async ({ params, request }) => {
        const runtime = createRequestContext(request)
        return withOwnerRepository(runtime, () =>
          ownerStatusResponse(request, params.id, getSecretRepository(runtime)),
        )
      },
      DELETE: async ({ params, request }) => {
        const runtime = createRequestContext(request)
        return withOwnerRepository(runtime, () =>
          ownerRevokeResponse(request, params.id, getSecretRepository(runtime)),
        )
      },
    },
  },
})
