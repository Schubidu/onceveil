import { createFileRoute } from '@tanstack/react-router'

import { ownerRevokeResponse, ownerStatusResponse } from '../runtime/owner-http'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { runtimeEnvironmentForRequest } from '../runtime/readiness'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

function jsonError(error: string, status: number): Response {
  return withSecretSecurityHeaders(Response.json({ error }, { status }))
}

async function withOwnerRepository(
  request: Request,
  operation: () => Promise<Response>,
): Promise<Response> {
  const expectedEnvironment = runtimeEnvironmentForRequest(request)
  if (!expectedEnvironment) {
    return jsonError('service_unavailable', 503)
  }

  try {
    await assertSecretDatabaseEnvironment(expectedEnvironment)
    return await operation()
  } catch (error) {
    if (error instanceof SecretDatabaseUnavailableError) {
      return jsonError('service_unavailable', 503)
    }

    if (error instanceof SecretDatabaseEnvironmentError) {
      console.error('secret database environment check failed', {
        expected: error.expected,
        actual: error.actual,
      })
      return jsonError('service_unavailable', 503)
    }

    console.error('secret owner operation failed', {
      name: error instanceof Error ? error.name : 'UnknownError',
      message: error instanceof Error ? error.message : 'unknown error',
    })
    return jsonError('internal_error', 500)
  }
}

export const Route = createFileRoute('/api/secrets/$id/owner')({
  server: {
    handlers: {
      GET: async ({ params, request }) =>
        withOwnerRepository(request, () =>
          ownerStatusResponse(request, params.id, getSecretRepository()),
        ),
      DELETE: async ({ params, request }) =>
        withOwnerRepository(request, () =>
          ownerRevokeResponse(request, params.id, getSecretRepository()),
        ),
    },
  },
})
