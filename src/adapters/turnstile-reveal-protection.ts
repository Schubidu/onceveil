import {
  REVEAL_PROTECTION_ACTION,
  type RevealChallengeContext,
  type RevealChallengeResult,
  type RevealChallengeVerifier,
} from '../core/reveal-protection'

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
const MAX_TOKEN_LENGTH = 2048

export interface TurnstileRevealProtectionConfiguration {
  siteKey: string
  secretKey: string
}

export function turnstileRevealProtectionConfiguration(
  siteKey: string | undefined,
  secretKey: string | undefined,
): TurnstileRevealProtectionConfiguration | undefined {
  const normalizedSiteKey = siteKey?.trim()
  const normalizedSecretKey = secretKey?.trim()
  if (!normalizedSiteKey || !normalizedSecretKey) {
    return undefined
  }

  return {
    siteKey: normalizedSiteKey,
    secretKey: normalizedSecretKey,
  }
}

interface SiteverifyResponse {
  success?: unknown
  hostname?: unknown
  action?: unknown
  cdata?: unknown
  'error-codes'?: unknown
}

export class TurnstileRevealChallengeVerifier implements RevealChallengeVerifier {
  constructor(
    private readonly secretKey: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async verify(context: RevealChallengeContext): Promise<RevealChallengeResult> {
    const token = context.token.trim()
    if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      return { kind: 'invalid' }
    }

    const expectedHostname = context.hostname.toLowerCase()
    if (!expectedHostname) {
      return { kind: 'invalid' }
    }

    const body = new FormData()
    body.set('secret', this.secretKey)
    body.set('response', token)
    if (context.remoteIp) {
      body.set('remoteip', context.remoteIp)
    }

    let response: Response
    try {
      const fetchImpl = this.fetchImpl
      response = await fetchImpl(SITEVERIFY_URL, {
        method: 'POST',
        body,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : ''
      const diagnostic = /network connection lost/i.test(message)
        ? 'siteverify_network_lost'
        : /1042|same.zone|another worker/i.test(message)
          ? 'siteverify_worker_routing'
          : /cannot access|host.*not.*allowed|requested a host/i.test(message)
            ? 'siteverify_host_blocked'
            : 'siteverify_fetch_failed'

      console.warn('Turnstile Siteverify fetch failed', {
        name: error instanceof Error ? error.name : 'UnknownError',
        diagnostic,
      })
      return { kind: 'unavailable', diagnostic }
    }

    if (!response.ok) {
      return { kind: 'unavailable', diagnostic: 'siteverify_http_error' }
    }

    let result: unknown
    try {
      result = await response.json()
    } catch {
      return { kind: 'unavailable', diagnostic: 'siteverify_invalid_response' }
    }

    if (typeof result !== 'object' || result === null) {
      return { kind: 'unavailable', diagnostic: 'siteverify_invalid_response' }
    }

    const siteverify = result as SiteverifyResponse
    const actionMatches = siteverify.action === REVEAL_PROTECTION_ACTION
    const hostnameMatches =
      typeof siteverify.hostname === 'string' &&
      siteverify.hostname.toLowerCase() === expectedHostname
    const cdataMatches = siteverify.cdata === context.secretId

    if (siteverify.success !== true || !actionMatches || !hostnameMatches || !cdataMatches) {
      const errorCodes = Array.isArray(siteverify['error-codes'])
        ? siteverify['error-codes']
            .filter((code): code is string => typeof code === 'string')
            .slice(0, 10)
        : []
      const diagnostic =
        siteverify.success !== true
          ? 'siteverify_rejected'
          : !hostnameMatches
            ? 'hostname_mismatch'
            : !actionMatches
              ? 'action_mismatch'
              : 'cdata_mismatch'

      console.warn('Turnstile Siteverify rejected reveal verification', {
        success: siteverify.success === true,
        errorCodes,
        hostnameMatches,
        actionMatches,
        cdataMatches,
      })
      return { kind: 'invalid', diagnostic }
    }

    return { kind: 'verified' }
  }
}
