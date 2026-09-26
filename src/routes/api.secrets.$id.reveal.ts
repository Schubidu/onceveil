import { createFileRoute } from '@tanstack/react-router'

import { revealSecretResponse } from '../runtime/secret-http'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

export const Route = createFileRoute('/api/secrets/$id/reveal')({
  server: {
    handlers: {
      POST: async ({ params, request }) => {
        if (request.headers.get('X-Onceveil-Reveal') !== '1') {
          return withSecretSecurityHeaders(
            Response.json({ error: 'reveal_intent_required' }, { status: 400 }),
          )
        }

        try {
          await assertSecretDatabaseEnvironment()
          return await revealSecretResponse(params.id, getSecretRepository())
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
                      error: 'database_environment_mismatch',
                      expected: error.expected,
                      actual: error.actual,
                    }
                  : { error: 'service_unavailable' },
                { status: 503 },
              ),
            )
          }

          console.error('secret reveal failed', {
            name: error instanceof Error ? error.name : 'UnknownError',
            message: error instanceof Error ? error.message : 'unknown error',
          })
          return withSecretSecurityHeaders(
            Response.json({ error: 'internal_error' }, { status: 500 }),
          )
        }
      },
    },
  },
})
