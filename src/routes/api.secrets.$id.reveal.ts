import { createFileRoute } from '@tanstack/react-router'

import { revealSecretResponse } from '../runtime/secret-http'
import { getSecretRepository, SecretDatabaseUnavailableError } from '../runtime/secret-repository'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

export const Route = createFileRoute('/api/secrets/$id/reveal')({
  server: {
    handlers: {
      POST: async ({ params }) => {
        try {
          return await revealSecretResponse(params.id, getSecretRepository())
        } catch (error) {
          if (error instanceof SecretDatabaseUnavailableError) {
            return withSecretSecurityHeaders(
              Response.json({ error: 'service_unavailable' }, { status: 503 }),
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
