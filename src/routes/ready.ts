import { createFileRoute } from '@tanstack/react-router'

import {
  checkSecretDatabaseReadiness,
  runtimeEnvironmentForRequest,
  type SecretDatabaseReadiness,
} from '../runtime/readiness'
import {
  getSecretDatabase,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'

export const Route = createFileRoute('/ready')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const expectedEnvironment = runtimeEnvironmentForRequest(request)
        let readiness: SecretDatabaseReadiness

        try {
          readiness = await checkSecretDatabaseReadiness(
            getSecretDatabase(),
            expectedEnvironment,
          )
        } catch (error) {
          if (!(error instanceof SecretDatabaseUnavailableError)) {
            throw error
          }

          readiness = { status: 'not_ready', database: 'unavailable' }
        }

        return Response.json(readiness, {
          status: readiness.status === 'ready' ? 200 : 503,
          headers: {
            'Cache-Control': 'no-store',
          },
        })
      },
    },
  },
})
