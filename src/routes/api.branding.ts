import { createFileRoute } from '@tanstack/react-router'

import { createRequestContext } from '#onceveil-runtime-context'

export const Route = createFileRoute('/api/branding')({
  server: {
    handlers: {
      GET: ({ request }) => {
        const runtime = createRequestContext(request)
        return Response.json(runtime.branding, {
          headers: {
            'Cache-Control': 'no-store',
          },
        })
      },
    },
  },
})
