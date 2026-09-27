import {
  createChallenge,
  randomInt,
  verifySolution,
  type Challenge,
  type Payload,
} from 'altcha-lib'
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2'

import {
  REVEAL_PROTECTION_ACTION,
  type RevealChallengeContext,
  type RevealChallengeResult,
  type RevealChallengeVerifier,
} from '../core/reveal-protection'
import type { SecretId } from '../core/secret'

const DEFAULT_COST = 5_000
const DEFAULT_COUNTER_MIN = 5_000
const DEFAULT_COUNTER_MAX = 10_000
const DEFAULT_CHALLENGE_TTL_MS = 2 * 60_000
const MIN_SECRET_LENGTH = 32

export interface AltchaChallengeOptions {
  cost: number
  counterMin: number
  counterMax: number
  challengeTtlMs: number
}

const DEFAULT_OPTIONS: AltchaChallengeOptions = {
  cost: DEFAULT_COST,
  counterMin: DEFAULT_COUNTER_MIN,
  counterMax: DEFAULT_COUNTER_MAX,
  challengeTtlMs: DEFAULT_CHALLENGE_TTL_MS,
}

export function isValidAltchaSecret(value: string | undefined): value is string {
  return typeof value === 'string' && value.trim().length >= MIN_SECRET_LENGTH
}

function parsePayload(token: string): Payload | undefined {
  try {
    const decoded = atob(token)
    const value: unknown = JSON.parse(decoded)
    if (
      typeof value !== 'object' ||
      value === null ||
      !('challenge' in value) ||
      !('solution' in value)
    ) {
      return undefined
    }

    return value as Payload
  } catch {
    return undefined
  }
}

function matchesContext(payload: Payload, secretId: SecretId, verificationId: string): boolean {
  const data = payload.challenge?.parameters?.data
  return (
    data?.action === REVEAL_PROTECTION_ACTION &&
    data?.secretId === secretId &&
    data?.verificationId === verificationId
  )
}

export class AltchaRevealProtection implements RevealChallengeVerifier {
  private readonly secretKey: string
  private readonly options: AltchaChallengeOptions

  constructor(secretKey: string, options: Partial<AltchaChallengeOptions> = {}) {
    if (!isValidAltchaSecret(secretKey)) {
      throw new TypeError('ALTCHA secret must contain at least 32 characters')
    }

    this.secretKey = secretKey.trim()
    this.options = { ...DEFAULT_OPTIONS, ...options }

    if (
      !Number.isSafeInteger(this.options.cost) ||
      this.options.cost < 1 ||
      !Number.isSafeInteger(this.options.counterMin) ||
      this.options.counterMin < 1 ||
      !Number.isSafeInteger(this.options.counterMax) ||
      this.options.counterMax < this.options.counterMin ||
      !Number.isSafeInteger(this.options.challengeTtlMs) ||
      this.options.challengeTtlMs < 1
    ) {
      throw new TypeError('Invalid ALTCHA challenge configuration')
    }
  }

  async createChallenge(
    secretId: SecretId,
    verificationId: string,
    nowMs = Date.now(),
  ): Promise<Challenge> {
    if (!/^[0-9a-f]{32}$/.test(verificationId) || !Number.isSafeInteger(nowMs)) {
      throw new TypeError('Invalid ALTCHA challenge context')
    }

    return createChallenge({
      algorithm: 'PBKDF2/SHA-256',
      cost: this.options.cost,
      counter: randomInt(this.options.counterMax, this.options.counterMin),
      deriveKey,
      expiresAt: new Date(nowMs + this.options.challengeTtlMs),
      hmacSignatureSecret: this.secretKey,
      data: {
        action: REVEAL_PROTECTION_ACTION,
        secretId,
        verificationId,
      },
    })
  }

  async verify(context: RevealChallengeContext): Promise<RevealChallengeResult> {
    const payload = parsePayload(context.token)
    if (!payload || !matchesContext(payload, context.secretId, context.verificationId)) {
      return { kind: 'invalid' }
    }

    try {
      const result = await verifySolution({
        challenge: payload.challenge,
        deriveKey,
        solution: payload.solution,
        hmacSignatureSecret: this.secretKey,
      })

      return result.verified ? { kind: 'verified' } : { kind: 'invalid' }
    } catch {
      return { kind: 'invalid' }
    }
  }
}
