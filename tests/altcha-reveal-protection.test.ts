import { solveChallenge } from 'altcha-lib'
import { deriveKey } from 'altcha-lib/algorithms/web/pbkdf2'
import { describe, expect, it } from 'vitest'

import {
  AltchaRevealProtection,
  altchaRevealProtectionConfiguration,
} from '../src/adapters/altcha-reveal-protection'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId
const VERIFICATION_ID = 'a'.repeat(32)
const HMAC_SECRET = 's'.repeat(32)

function token(payload: unknown): string {
  return btoa(JSON.stringify(payload))
}

async function solvedToken(provider: AltchaRevealProtection) {
  const challenge = await provider.createChallenge(SECRET_ID, VERIFICATION_ID)
  const solution = await solveChallenge({
    challenge,
    deriveKey,
    timeout: 5_000,
  })
  if (!solution) {
    throw new Error('ALTCHA test challenge was not solved')
  }

  return {
    challenge,
    token: token({ challenge, solution }),
  }
}

describe('ALTCHA reveal protection', () => {
  it('requires a sufficiently long HMAC secret', () => {
    expect(altchaRevealProtectionConfiguration(HMAC_SECRET)).toEqual({
      hmacSecret: HMAC_SECRET,
    })
    expect(altchaRevealProtectionConfiguration(undefined)).toBeUndefined()
    expect(altchaRevealProtectionConfiguration('too-short')).toBeUndefined()
  })

  it('uses the signed-key fast path for the default challenge profile', async () => {
    const provider = new AltchaRevealProtection(HMAC_SECRET)
    const challenge = await provider.createChallenge(SECRET_ID, VERIFICATION_ID)

    expect(challenge.parameters).toMatchObject({
      algorithm: 'PBKDF2/SHA-256',
      cost: 5_000,
      keyLength: 32,
      keyPrefix: expect.stringMatching(/^[0-9a-f]{32}$/i),
      keySignature: expect.stringMatching(/^[0-9a-f]{64}$/i),
    })
    expect(challenge.signature).toMatch(/^[0-9a-f]{64}$/i)
  })

  it('verifies a challenge bound to the secret and verification id', async () => {
    const provider = new AltchaRevealProtection(HMAC_SECRET, {
      cost: 1,
      counterMin: 1,
      counterMax: 2,
    })
    const solved = await solvedToken(provider)

    await expect(
      provider.verify({
        token: solved.token,
        secretId: SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'verified' })
  })

  it('rejects replay against a different verification id', async () => {
    const provider = new AltchaRevealProtection(HMAC_SECRET, {
      cost: 1,
      counterMin: 1,
      counterMax: 2,
    })
    const solved = await solvedToken(provider)

    await expect(
      provider.verify({
        token: solved.token,
        secretId: SECRET_ID,
        verificationId: 'b'.repeat(32),
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })

  it('rejects a signed challenge from a different PBKDF2 cost profile', async () => {
    const issuer = new AltchaRevealProtection(HMAC_SECRET, {
      cost: 1,
      counterMin: 1,
      counterMax: 2,
    })
    const solved = await solvedToken(issuer)
    const defaultProvider = new AltchaRevealProtection(HMAC_SECRET)

    await expect(
      defaultProvider.verify({
        token: solved.token,
        secretId: SECRET_ID,
        verificationId: VERIFICATION_ID,
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })

  it('rejects a challenge whose signed binding was modified', async () => {
    const provider = new AltchaRevealProtection(HMAC_SECRET, {
      cost: 1,
      counterMin: 1,
      counterMax: 2,
    })
    const challenge = await provider.createChallenge(SECRET_ID, VERIFICATION_ID)
    const solution = await solveChallenge({
      challenge,
      deriveKey,
      timeout: 5_000,
    })
    if (!solution) {
      throw new Error('ALTCHA test challenge was not solved')
    }

    challenge.parameters.data = {
      ...challenge.parameters.data,
      verificationId: 'b'.repeat(32),
    }

    await expect(
      provider.verify({
        token: token({ challenge, solution }),
        secretId: SECRET_ID,
        verificationId: 'b'.repeat(32),
        hostname: 'localhost',
      }),
    ).resolves.toEqual({ kind: 'invalid' })
  })

  it('rejects malformed payloads without exposing provider errors', async () => {
    const provider = new AltchaRevealProtection(HMAC_SECRET, {
      cost: 1,
      counterMin: 1,
      counterMax: 2,
    })

    for (const malformedToken of ['not-base64-json', token({ challenge: {}, solution: {} })]) {
      await expect(
        provider.verify({
          token: malformedToken,
          secretId: SECRET_ID,
          verificationId: VERIFICATION_ID,
          hostname: 'localhost',
        }),
      ).resolves.toEqual({ kind: 'invalid' })
    }
  })
})
