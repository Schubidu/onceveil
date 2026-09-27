import { createFileRoute } from '@tanstack/react-router'

import { checkSecretDatabaseReadiness } from '../runtime/readiness'
import { getSecretDatabase, SecretDatabaseUnavailableError } from '../runtime/secret-repository'

export const Route = createFileRoute('/ready')({
  server: {
    handlers: {
      GET: async ({ context }) => {
        let ready = false

        try {
          const readiness = await checkSecretDatabaseReadiness(
            getSecretDatabase(context),
            context.expectedDatabaseEnvironment,
          )
          ready = readiness.status === 'ready'
        } catch (error) {
          if (!(error instanceof SecretDatabaseUnavailableError)) {
            throw error
          }
        }

        return Response.json(
          { status: ready ? 'ready' : 'not_ready' },
          {
            status: ready ? 200 : 503,
            headers: {
              'Cache-Control': 'no-store',
            },
          },
        )
      },
    },
  },
})
