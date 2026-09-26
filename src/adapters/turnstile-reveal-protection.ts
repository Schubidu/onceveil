import {
  REVEAL_PROTECTION_ACTION,
  type RevealChallengeContext,
  type RevealChallengeResult,
  type RevealChallengeVerifier,
} from '../core/reveal-protection'

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
const MAX_TOKEN_LENGTH = 2048
const VERIFY_TIMEOUT_MS = 5_000

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

    let result: SiteverifyResponse
    try {
      result = (await response.json()) as SiteverifyResponse
    } catch {
      return { kind: 'unavailable' }
    }

    if (
      result.success !== true ||
      result.action !== REVEAL_PROTECTION_ACTION ||
      typeof result.hostname !== 'string' ||
      result.hostname.toLowerCase() !== expectedHostname ||
      result.cdata !== context.secretId
    ) {
      return { kind: 'invalid' }
    }

    return { kind: 'verified' }
  }
}
