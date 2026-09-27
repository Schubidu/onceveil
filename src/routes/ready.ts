import { createFileRoute } from '@tanstack/react-router'

import { createRequestContext } from '#onceveil-runtime-context'
import { checkSecretDatabaseReadiness } from '../runtime/readiness'
import { getSecretDatabase, SecretDatabaseUnavailableError } from '../runtime/secret-repository'

export const Route = createFileRoute('/ready')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const runtime = createRequestContext(request)
        let ready = false

        try {
          const expectedEnvironment =
            runtime.databaseEnvironment === 'production' ||
            runtime.databaseEnvironment === 'preview'
              ? runtime.databaseEnvironment
              : undefined
          const readiness = await checkSecretDatabaseReadiness(
            getSecretDatabase(runtime),
            expectedEnvironment,
          )
          ready =
            readiness.status === 'ready' && runtime.revealProtection.provider !== 'unavailable'
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
