import { createFileRoute } from '@tanstack/react-router'

import { createSecretResponse } from '../runtime/secret-http'
import {
  getSecretRepository,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

export const Route = createFileRoute('/api/secrets')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        try {
          return await createSecretResponse(request, getSecretRepository())
        } catch (error) {
          if (error instanceof SecretDatabaseUnavailableError) {
            return withSecretSecurityHeaders(
              Response.json({ error: 'service_unavailable' }, { status: 503 }),
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
