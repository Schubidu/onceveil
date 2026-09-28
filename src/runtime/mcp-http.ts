import { createRequestContext } from '#onceveil-runtime-context'

import { createOnceveilMcpHandler } from './mcp-server'
import { assertSecretDatabaseEnvironment } from './secret-repository'

const encoder = new TextEncoder()

async function tokenDigest(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))
}

async function tokenMatches(expected: string, actual: string): Promise<boolean> {
  const [expectedDigest, actualDigest] = await Promise.all([
    tokenDigest(expected),
    tokenDigest(actual),
  ])
  let difference = 0
  for (let index = 0; index < expectedDigest.length; index += 1) {
    difference |= expectedDigest[index] ^ actualDigest[index]
  }
  return difference === 0
}

function bearerToken(request: Request): string | undefined {
  const authorization = request.headers.get('Authorization')
  return authorization?.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : undefined
}

function protectedResponse(response: Response): Response {
  const headers = new Headers(response.headers)
  headers.set('Cache-Control', 'no-store')
  headers.set('Referrer-Policy', 'no-referrer')
  headers.set('X-Content-Type-Options', 'nosniff')

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

export async function handleMcpRequest(request: Request): Promise<Response> {
  const context = createRequestContext(request)
  if (context.mcp.status === 'disabled') {
    return protectedResponse(new Response(null, { status: 404 }))
  }

  if (context.mcp.status !== 'enabled') {
    return protectedResponse(Response.json({ error: 'service_unavailable' }, { status: 503 }))
  }

  const token = bearerToken(request)
  if (!token || !(await tokenMatches(context.mcp.authToken, token))) {
    return protectedResponse(
      Response.json(
        { error: 'unauthorized' },
        {
          status: 401,
          headers: { 'WWW-Authenticate': 'Bearer' },
        },
      ),
    )
  }

  try {
    await assertSecretDatabaseEnvironment(context)
  } catch {
    return protectedResponse(Response.json({ error: 'service_unavailable' }, { status: 503 }))
  }

  const handler = await createOnceveilMcpHandler(context)
  try {
    return protectedResponse(await handler.fetch(request))
  } finally {
    await handler.close()
  }
}
