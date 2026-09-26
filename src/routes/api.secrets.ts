import { createFileRoute } from '@tanstack/react-router'

import { D1CreateError } from '../adapters/d1-secret-repository'
import { createSecretResponse } from '../runtime/secret-http'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

export const Route = createFileRoute('/api/secrets')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        try {
          await assertSecretDatabaseEnvironment()
          return await createSecretResponse(request, getSecretRepository())
        } catch (error) {
          if (error instanceof SecretDatabaseUnavailableError) {
            return withSecretSecurityHeaders(
              Response.json({ error: 'service_unavailable' }, { status: 503 }),
            )
          }

          if (error instanceof SecretDatabaseEnvironmentError) {
            const hostname = new URL(request.url).hostname
            const isPreview =
              hostname.endsWith('.ots-preview.schult.dev') ||
              hostname.endsWith('-onceveil.schult.workers.dev')

            return withSecretSecurityHeaders(
              Response.json(
                isPreview
                  ? {
                      error: `database_environment_mismatch expected=${error.expected} actual=${error.actual}`,
                      expected: error.expected,
                      actual: error.actual,
                    }
                  : { error: 'service_unavailable' },
                { status: 503 },
              ),
            )
          }

          console.error('secret create failed', {
            name: error instanceof Error ? error.name : 'UnknownError',
            message: error instanceof Error ? error.message : 'unknown error',
          })

          if (error instanceof D1CreateError) {
            const hostname = new URL(request.url).hostname
            const isPreview =
              hostname.endsWith('.ots-preview.schult.dev') ||
              hostname.endsWith('-onceveil.schult.workers.dev')

            if (isPreview) {
              return withSecretSecurityHeaders(
                Response.json(
                  {
                    error: 'd1_create_failed',
                    stage: error.stage,
                    detail: error.detail,
                  },
                  { status: 500 },
                ),
              )
            }
          }

          return withSecretSecurityHeaders(
            Response.json({ error: 'internal_error' }, { status: 500 }),
          )
        }
      },
    },
  },
})
