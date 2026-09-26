import type { D1DatabaseLike, D1ResultLike } from './d1-secret-repository'
import {
  REVEAL_PROOF_TTL_MS,
  REVEAL_VERIFICATION_TTL_MS,
  type RevealProof,
  type RevealProofRepository,
} from '../core/reveal-protection'
import type { SecretId } from '../core/secret'

const PROOF_BYTES = 32
const VERIFICATION_BYTES = 16
const PROOF_ATTEMPTS = 3
const PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/
const VERIFICATION_PATTERN = /^[0-9a-f]{32}$/

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function randomProof(): string {
  const bytes = new Uint8Array(PROOF_BYTES)
  crypto.getRandomValues(bytes)
  return encodeBase64Url(bytes)
}

function randomVerificationId(): string {
  const bytes = new Uint8Array(VERIFICATION_BYTES)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function proofHash(proof: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(proof)),
  )
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export class RevealProofStorageError extends Error {
  constructor() {
    super('Reveal proof storage is unavailable')
    this.name = 'RevealProofStorageError'
  }
}

export class D1RevealProofRepository implements RevealProofRepository {
  constructor(private readonly db: D1DatabaseLike) {}

  async prepare(secretId: SecretId, nowMs: number): Promise<RevealProof> {
    if (!Number.isSafeInteger(nowMs)) {
      throw new RevealProofStorageError()
    }

    const expiresAtMs = nowMs + REVEAL_VERIFICATION_TTL_MS
    if (!Number.isSafeInteger(expiresAtMs)) {
      throw new RevealProofStorageError()
    }

    const session = this.db.withSession('first-primary')

    let cleanup: D1ResultLike
    try {
      cleanup = await session
        .prepare(
          `DELETE FROM reveal_proofs
           WHERE consumed_at_ms IS NOT NULL OR expires_at_ms <= ?`,
        )
        .bind(nowMs)
        .run()
    } catch {
      throw new RevealProofStorageError()
    }

    if (!cleanup.success) {
      throw new RevealProofStorageError()
    }

    for (let attempt = 0; attempt < PROOF_ATTEMPTS; attempt += 1) {
      const value = randomProof()
      const verificationId = randomVerificationId()
      const hash = await proofHash(value)

      let result: D1ResultLike
      try {
        result = await session
          .prepare(
            `INSERT OR IGNORE INTO reveal_proofs
              (proof_hash, verification_id, secret_id, issued_at_ms, expires_at_ms, verified_at_ms, consumed_at_ms)
             VALUES (?, ?, ?, ?, ?, NULL, NULL)`,
          )
          .bind(hash, verificationId, secretId, nowMs, expiresAtMs)
          .run()
      } catch {
        throw new RevealProofStorageError()
      }

      if (!result.success) {
        throw new RevealProofStorageError()
      }

      if (result.meta?.changes === 1) {
        return { value, verificationId, expiresAtMs }
      }
    }

    throw new RevealProofStorageError()
  }

  async verify(secretId: SecretId, verificationId: string, nowMs: number): Promise<boolean> {
    if (!VERIFICATION_PATTERN.test(verificationId) || !Number.isSafeInteger(nowMs)) {
      return false
    }

    const expiresAtMs = nowMs + REVEAL_PROOF_TTL_MS
    if (!Number.isSafeInteger(expiresAtMs)) {
      throw new RevealProofStorageError()
    }

    const session = this.db.withSession('first-primary')

    let result: D1ResultLike
    try {
      result = await session
        .prepare(
          `UPDATE reveal_proofs
           SET verified_at_ms = ?, expires_at_ms = ?
           WHERE verification_id = ?
             AND secret_id = ?
             AND verified_at_ms IS NULL
             AND consumed_at_ms IS NULL
             AND expires_at_ms > ?`,
        )
        .bind(nowMs, expiresAtMs, verificationId, secretId, nowMs)
        .run()
    } catch {
      throw new RevealProofStorageError()
    }

    if (!result.success) {
      throw new RevealProofStorageError()
    }

    return result.meta?.changes === 1
  }

  async consume(secretId: SecretId, proof: string, nowMs: number): Promise<boolean> {
    if (!PROOF_PATTERN.test(proof) || !Number.isSafeInteger(nowMs)) {
      return false
    }

    const hash = await proofHash(proof)
    const session = this.db.withSession('first-primary')

    let result: D1ResultLike
    try {
      result = await session
        .prepare(
          `UPDATE reveal_proofs
           SET consumed_at_ms = ?
           WHERE proof_hash = ?
             AND secret_id = ?
             AND verified_at_ms IS NOT NULL
             AND consumed_at_ms IS NULL
             AND expires_at_ms > ?`,
        )
        .bind(nowMs, hash, secretId, nowMs)
        .run()
    } catch {
      throw new RevealProofStorageError()
    }

    if (!result.success) {
      throw new RevealProofStorageError()
    }

    return result.meta?.changes === 1
  }
}
