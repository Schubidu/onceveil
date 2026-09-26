import { createFileRoute } from '@tanstack/react-router'

import { checkSecretDatabaseReadiness, runtimeEnvironmentForRequest } from '../runtime/readiness'
import { getSecretDatabase, SecretDatabaseUnavailableError } from '../runtime/secret-repository'

export const Route = createFileRoute('/ready')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const expectedEnvironment = runtimeEnvironmentForRequest(request)
        if (!expectedEnvironment) {
          return Response.json(
            { status: 'not_ready' },
            {
              status: 503,
              headers: { 'Cache-Control': 'no-store' },
            },
          )
        }

        let ready = false

        try {
          const readiness = await checkSecretDatabaseReadiness(
            getSecretDatabase(),
            expectedEnvironment,
          )
          ready = readiness.status === 'ready'
        } catch (error) {
          if (!(error instanceof SecretDatabaseUnavailableError)) {
            throw error
          }

        }

        return Response.json({ status: ready ? 'ready' : 'not_ready' }, {
          status: ready ? 200 : 503,
          headers: {
            'Cache-Control': 'no-store',
          },
        })
      },
    },
  },
})
