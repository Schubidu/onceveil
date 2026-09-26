export type SecretSurfacePolicy = 'isolated' | 'turnstile'

const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/

const BASE_DIRECTIVES = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "worker-src 'none'",
]

function contentSecurityPolicy(
  policy: SecretSurfacePolicy,
  frameAncestor?: string,
): string {
  const turnstile = policy === 'turnstile'
  return [
    ...BASE_DIRECTIVES,
    turnstile && frameAncestor ? `frame-ancestors ${frameAncestor}` : "frame-ancestors 'none'",
    turnstile
      ? "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com"
      : "script-src 'self' 'unsafe-inline'",
    turnstile ? "connect-src 'self' https://challenges.cloudflare.com" : "connect-src 'self'",
    turnstile ? 'frame-src https://challenges.cloudflare.com' : "frame-src 'none'",
  ].join('; ')
}

export function secretSecurityHeaders(
  policy: SecretSurfacePolicy = 'isolated',
  frameAncestor?: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': contentSecurityPolicy(policy, frameAncestor),
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy':
      policy === 'turnstile' && frameAncestor ? 'cross-origin' : 'same-origin',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  }

  if (!(policy === 'turnstile' && frameAncestor)) {
    headers['X-Frame-Options'] = 'DENY'
  }

  return headers
}

export function withSecretSecurityHeaders(
  response: Response,
  policy: SecretSurfacePolicy = 'isolated',
  frameAncestor?: string,
): Response {
  const headers = new Headers(response.headers)
  for (const [name, value] of Object.entries(secretSecurityHeaders(policy, frameAncestor))) {
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
    pathname.startsWith('/o/') ||
    pathname.startsWith('/s/')
  )
}

export function secretSurfacePolicy(request: Request): SecretSurfacePolicy {
  const url = new URL(request.url)
  const verificationId = url.searchParams.get('verification')
  return url.pathname.startsWith('/s/') &&
    url.searchParams.get('verify') === 'turnstile' &&
    verificationId !== null &&
    VERIFICATION_ID_PATTERN.test(verificationId)
    ? 'turnstile'
    : 'isolated'
}
