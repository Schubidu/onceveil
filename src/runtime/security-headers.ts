export type SecretSurfacePolicy = 'isolated' | 'verification'

const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/

function contentSecurityPolicy(
  policy: SecretSurfacePolicy,
  frameAncestor?: string,
  frameSource?: string,
  documentOrigin?: string,
): string {
  const verification = policy === 'verification'
  const assetSource = verification && documentOrigin ? documentOrigin : "'self'"
  return [
    "default-src 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "form-action 'self'",
    `img-src ${assetSource} data:`,
    `font-src ${assetSource}`,
    `style-src ${assetSource} 'unsafe-inline'`,
    "worker-src 'none'",
    verification && frameAncestor ? `frame-ancestors ${frameAncestor}` : "frame-ancestors 'none'",
    verification
      ? `script-src ${assetSource} 'unsafe-inline' https://challenges.cloudflare.com`
      : "script-src 'self' 'unsafe-inline'",
    verification
      ? `connect-src ${assetSource} https://challenges.cloudflare.com`
      : "connect-src 'self'",
    verification
      ? 'frame-src https://challenges.cloudflare.com'
      : frameSource
        ? `frame-src ${frameSource}`
        : "frame-src 'none'",
  ].join('; ')
}

export function secretSecurityHeaders(
  policy: SecretSurfacePolicy = 'isolated',
  frameAncestor?: string,
  frameSource?: string,
  documentOrigin?: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': contentSecurityPolicy(
      policy,
      frameAncestor,
      frameSource,
      documentOrigin,
    ),
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  }

  if (policy === 'isolated') {
    headers['X-Frame-Options'] = 'DENY'
  }

  return headers
}

export function withSecretSecurityHeaders(
  response: Response,
  policy: SecretSurfacePolicy = 'isolated',
  frameAncestor?: string,
  frameSource?: string,
  documentOrigin?: string,
): Response {
  const headers = new Headers(response.headers)
  for (const [name, value] of Object.entries(
    secretSecurityHeaders(policy, frameAncestor, frameSource, documentOrigin),
  )) {
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
    url.searchParams.get('verify') === '1' &&
    verificationId !== null &&
    VERIFICATION_ID_PATTERN.test(verificationId)
    ? 'verification'
    : 'isolated'
}
