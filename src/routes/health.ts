import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/health')({
  server: {
    handlers: {
      GET: () =>
        Response.json(
          {
            service: 'onceveil',
            status: 'ok',
          },
          {
            headers: {
              'Cache-Control': 'no-store',
            },
          },
        ),
    },
  },
})
