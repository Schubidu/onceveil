import {
  REVEAL_PROTECTION_ACTION,
  type RevealChallengeContext,
  type RevealChallengeResult,
  type RevealChallengeVerifier,
} from '../core/reveal-protection'

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
const MAX_TOKEN_LENGTH = 2048
const VERIFY_TIMEOUT_MS = 5_000

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

    const body = new URLSearchParams({
      secret: this.secretKey,
      response: token,
    })
    if (context.remoteIp) {
      body.set('remoteip', context.remoteIp)
    }

    let response: Response
    try {
      response = await this.fetchImpl(SITEVERIFY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
      })
    } catch {
      return { kind: 'unavailable' }
    }

    if (!response.ok) {
      return { kind: 'unavailable' }
    }

    let result: unknown
    try {
      result = await response.json()
    } catch {
      return { kind: 'unavailable' }
    }

    if (typeof result !== 'object' || result === null) {
      return { kind: 'unavailable' }
    }

    const siteverify = result as SiteverifyResponse
    if (
      siteverify.success !== true ||
      siteverify.action !== REVEAL_PROTECTION_ACTION ||
      typeof siteverify.hostname !== 'string' ||
      siteverify.hostname.toLowerCase() !== expectedHostname ||
      siteverify.cdata !== context.secretId
    ) {
      return { kind: 'invalid' }
    }

    return { kind: 'verified' }
  }
}
