import type { RevealProtectionRuntime } from './request-context'

export type SecretSurfacePolicy = 'isolated' | 'turnstile' | 'altcha'
export type RevealProtectionProvider = RevealProtectionRuntime['provider']

const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/

const BASE_DIRECTIVES = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "style-src 'self' 'unsafe-inline'",
]

function contentSecurityPolicy(policy: SecretSurfacePolicy): string {
  const turnstile = policy === 'turnstile'
  const altcha = policy === 'altcha'

  return [
    ...BASE_DIRECTIVES,
    turnstile
      ? "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com"
      : "script-src 'self' 'unsafe-inline'",
    turnstile ? "connect-src 'self' https://challenges.cloudflare.com" : "connect-src 'self'",
    turnstile ? 'frame-src https://challenges.cloudflare.com' : "frame-src 'none'",
    altcha ? "worker-src 'self' blob:" : "worker-src 'none'",
  ].join('; ')
}

export function secretSecurityHeaders(policy: SecretSurfacePolicy = 'isolated') {
  return {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': contentSecurityPolicy(policy),
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  } as const
}

export function withSecretSecurityHeaders(
  response: Response,
  policy: SecretSurfacePolicy = 'isolated',
): Response {
  const headers = new Headers(response.headers)
  for (const [name, value] of Object.entries(secretSecurityHeaders(policy))) {
    headers.set(name, value)
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

export function isSecretSurface(request: Request): boolean {
  const pathname = new URL(request.url).pathname
  return (
    pathname === '/' ||
    pathname === '/api/secrets' ||
    pathname.startsWith('/api/secrets/') ||
    pathname.startsWith('/api/mcp/handoffs/') ||
    pathname.startsWith('/mcp/handoff/') ||
    pathname.startsWith('/o/') ||
    pathname.startsWith('/s/')
  )
}

export function secretSurfacePolicy(
  request: Request,
  provider: RevealProtectionProvider,
): SecretSurfacePolicy {
  const url = new URL(request.url)
  const verificationId = url.searchParams.get('verification')
  const verificationSurface =
    url.pathname.startsWith('/s/') &&
    url.searchParams.get('verify') === '1' &&
    verificationId !== null &&
    VERIFICATION_ID_PATTERN.test(verificationId)

  if (!verificationSurface) {
    return 'isolated'
  }

  return provider === 'turnstile' || provider === 'altcha' ? provider : 'isolated'
}
