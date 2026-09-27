import { solveChallenge } from 'altcha-lib'
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2'
import { describe, expect, it } from 'vitest'

import {
  AltchaRevealProtection,
  isValidAltchaSecret,
} from '../src/adapters/altcha-reveal-protection'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId
const OTHER_SECRET_ID = 'fedcba9876543210fedcba9876543210' as SecretId
const VERIFICATION_ID = 'a'.repeat(32)
const SECRET_KEY = 's'.repeat(64)

function verifier(secretKey = SECRET_KEY) {
  return new AltchaRevealProtection(secretKey, {
    cost: 1,
    counterMin: 1,
    counterMax: 3,
    challengeTtlMs: 60_000,
  })
}

async function tokenFor(
  protection: AltchaRevealProtection,
  secretId = SECRET_ID,
  verificationId = VERIFICATION_ID,
  nowMs = Date.now(),
): Promise<string> {
  const challenge = await protection.createChallenge(secretId, verificationId, nowMs)
  const solution = await solveChallenge({ challenge, deriveKey })
  if (!solution) {
    throw new Error('ALTCHA test challenge was not solved')
  }

  return btoa(JSON.stringify({ challenge, solution }))
}

describe('ALTCHA reveal protection', () => {
  it('requires a sufficiently strong configured secret', () => {
    expect(isValidAltchaSecret(SECRET_KEY)).toBe(true)
    expect(isValidAltchaSecret('too-short')).toBe(false)
    expect(isValidAltchaSecret(undefined)).toBe(false)
    expect(() => new AltchaRevealProtection('too-short')).toThrow(/at least 32 characters/)
  })

  it('verifies a locally generated challenge bound to the reveal context', async () => {
    const protection = verifier()
    const token = await tokenFor(protection)

    await expect(
      protection.verify({
        token,
        secretId: SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'verified' })
  })

  it('rejects a valid solution when the secret or verification binding differs', async () => {
    const protection = verifier()
    const token = await tokenFor(protection)

    await expect(
      protection.verify({
        token,
        secretId: OTHER_SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })

    await expect(
      protection.verify({
        token,
        secretId: SECRET_ID,
        verificationId: 'b'.repeat(32),
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })

  it('rejects a solution signed by another ALTCHA secret', async () => {
    const issuer = verifier()
    const token = await tokenFor(issuer)
    const verifierWithOtherSecret = verifier('x'.repeat(64))

    await expect(
      verifierWithOtherSecret.verify({
        token,
        secretId: SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })

  it('rejects expired and malformed challenge payloads', async () => {
    const protection = new AltchaRevealProtection(SECRET_KEY, {
      cost: 1,
      counterMin: 1,
      counterMax: 1,
      challengeTtlMs: 1,
    })
    const expiredToken = await tokenFor(protection, SECRET_ID, VERIFICATION_ID, Date.now() - 60_000)

    await expect(
      protection.verify({
        token: expiredToken,
        secretId: SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })

    await expect(
      protection.verify({
        token: 'not-base64-json',
        secretId: SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })
})
