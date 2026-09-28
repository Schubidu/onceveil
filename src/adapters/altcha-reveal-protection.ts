import {
  createChallenge,
  randomInt,
  verifySolution,
  type Challenge,
  type Payload,
} from 'altcha-lib'
import { deriveKey } from 'altcha-lib/algorithms/web/pbkdf2'

import {
  REVEAL_PROTECTION_ACTION,
  REVEAL_VERIFICATION_TTL_MS,
  type RevealChallengeContext,
  type RevealChallengeResult,
  type RevealChallengeVerifier,
} from '../core/reveal-protection'
import type { SecretId } from '../core/secret'

const ALGORITHM = 'PBKDF2/SHA-256'
const DEFAULT_COST = 5_000
const DEFAULT_COUNTER_MIN = 5_000
const DEFAULT_COUNTER_MAX = 10_000
const MAX_TOKEN_LENGTH = 16 * 1024
const MIN_HMAC_SECRET_LENGTH = 32

export interface AltchaRevealProtectionConfiguration {
  hmacSecret: string
}

interface AltchaChallengeSettings {
  cost: number
  counterMin: number
  counterMax: number
}

const DEFAULT_SETTINGS: AltchaChallengeSettings = {
  cost: DEFAULT_COST,
  counterMin: DEFAULT_COUNTER_MIN,
  counterMax: DEFAULT_COUNTER_MAX,
}

export function altchaRevealProtectionConfiguration(
  hmacSecret: string | undefined,
): AltchaRevealProtectionConfiguration | undefined {
  const normalized = hmacSecret?.trim()
  if (!normalized || normalized.length < MIN_HMAC_SECRET_LENGTH) {
    return undefined
  }

  return { hmacSecret: normalized }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isPayload(value: unknown): value is Payload {
  if (!isRecord(value) || !isRecord(value.challenge) || !isRecord(value.solution)) {
    return false
  }

  const parameters = value.challenge.parameters
  if (!isRecord(parameters)) {
    return false
  }

  return (
    typeof parameters.algorithm === 'string' &&
    typeof parameters.nonce === 'string' &&
    typeof parameters.salt === 'string' &&
    typeof parameters.cost === 'number' &&
    Number.isFinite(parameters.cost) &&
    typeof parameters.keyLength === 'number' &&
    Number.isFinite(parameters.keyLength) &&
    typeof parameters.keyPrefix === 'string' &&
    (value.challenge.signature === undefined || typeof value.challenge.signature === 'string') &&
    typeof value.solution.counter === 'number' &&
    Number.isFinite(value.solution.counter) &&
    typeof value.solution.derivedKey === 'string'
  )
}

function decodePayload(token: string): Payload | undefined {
  const normalized = token.trim()
  if (normalized.length === 0 || normalized.length > MAX_TOKEN_LENGTH) {
    return undefined
  }

  try {
    const decoded = atob(normalized)
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0))
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    return isPayload(value) ? value : undefined
  } catch {
    return undefined
  }
}

function challengeMatchesContext(
  challenge: Challenge,
  secretId: SecretId,
  verificationId: string,
): boolean {
  const data = challenge.parameters?.data
  return (
    data?.action === REVEAL_PROTECTION_ACTION &&
    data.secretId === secretId &&
    data.verificationId === verificationId
  )
}

export class AltchaRevealProtection implements RevealChallengeVerifier {
  constructor(
    private readonly hmacSecret: string,
    private readonly settings: AltchaChallengeSettings = DEFAULT_SETTINGS,
  ) {}

  async createChallenge(
    secretId: SecretId,
    verificationId: string,
    nowMs = Date.now(),
  ): Promise<Challenge> {
    return createChallenge({
      algorithm: ALGORITHM,
      cost: this.settings.cost,
      counter: randomInt(this.settings.counterMax, this.settings.counterMin),
      data: {
        action: REVEAL_PROTECTION_ACTION,
        secretId,
        verificationId,
      },
      deriveKey,
      expiresAt: new Date(nowMs + REVEAL_VERIFICATION_TTL_MS),
      hmacSignatureSecret: this.hmacSecret,
    })
  }

  async verify(context: RevealChallengeContext): Promise<RevealChallengeResult> {
    const payload = decodePayload(context.token)
    if (!payload) {
      return { kind: 'invalid' }
    }

    try {
      const result = await verifySolution({
        challenge: payload.challenge,
        solution: payload.solution,
        deriveKey,
        hmacSignatureSecret: this.hmacSecret,
      })

      if (
        !result.verified ||
        !challengeMatchesContext(payload.challenge, context.secretId, context.verificationId)
      ) {
        return { kind: 'invalid' }
      }

      return { kind: 'verified' }
    } catch {
      return { kind: 'unavailable' }
    }
  }
}
