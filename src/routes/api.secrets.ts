import { createFileRoute } from '@tanstack/react-router'

import { D1CreateError } from '../adapters/d1-secret-repository'
import { createSecretResponse } from '../runtime/secret-http'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { runtimeEnvironmentForRequest } from '../runtime/readiness'
import { logRuntimeError } from '../runtime/safe-log'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

export const Route = createFileRoute('/api/secrets')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const expectedEnvironment = runtimeEnvironmentForRequest(request)
        if (!expectedEnvironment) {
          return withSecretSecurityHeaders(
            Response.json({ error: 'service_unavailable' }, { status: 503 }),
          )
        }

        try {
          await assertSecretDatabaseEnvironment(expectedEnvironment)
          return await createSecretResponse(request, getSecretRepository())
        } catch (error) {
          if (error instanceof SecretDatabaseUnavailableError) {
            return withSecretSecurityHeaders(
              Response.json({ error: 'service_unavailable' }, { status: 503 }),
            )
          }

          if (error instanceof SecretDatabaseEnvironmentError) {
            logRuntimeError('secret database environment check failed', error, {
              expected: error.expected,
              diagnostic: error.actual.startsWith('query-error:')
                ? 'query_error'
                : 'environment_mismatch',
            })
            return withSecretSecurityHeaders(
              Response.json({ error: 'service_unavailable' }, { status: 503 }),
            )
          }

          logRuntimeError(
            'secret create failed',
            error,
            error instanceof D1CreateError ? { stage: error.stage } : {},
          )

          if (error instanceof D1CreateError) {
            return withSecretSecurityHeaders(
              Response.json({ error: 'internal_error' }, { status: 500 }),
            )
          }

          return withSecretSecurityHeaders(
            Response.json({ error: 'internal_error' }, { status: 500 }),
          )
        }
      },
    },
  },
})
