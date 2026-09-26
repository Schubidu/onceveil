import type { D1DatabaseLike, D1ResultLike } from './d1-secret-repository'
import {
  REVEAL_PROOF_TTL_MS,
  type RevealProof,
  type RevealProofRepository,
} from '../core/reveal-protection'
import type { SecretId } from '../core/secret'

const PROOF_BYTES = 32
const PROOF_ATTEMPTS = 3
const PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/

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

  async issue(secretId: SecretId, nowMs: number): Promise<RevealProof> {
    if (!Number.isSafeInteger(nowMs)) {
      throw new RevealProofStorageError()
    }

    const expiresAtMs = nowMs + REVEAL_PROOF_TTL_MS
    if (!Number.isSafeInteger(expiresAtMs)) {
      throw new RevealProofStorageError()
    }

    const session = this.db.withSession('first-primary')

    for (let attempt = 0; attempt < PROOF_ATTEMPTS; attempt += 1) {
      const value = randomProof()
      const hash = await proofHash(value)

      let result: D1ResultLike
      try {
        result = await session
          .prepare(
            `INSERT OR IGNORE INTO reveal_proofs
              (proof_hash, secret_id, issued_at_ms, expires_at_ms, consumed_at_ms)
             VALUES (?, ?, ?, ?, NULL)`,
          )
          .bind(hash, secretId, nowMs, expiresAtMs)
          .run()
      } catch {
        throw new RevealProofStorageError()
      }

      if (!result.success) {
        throw new RevealProofStorageError()
      }

      if (result.meta?.changes === 1) {
        return { value, expiresAtMs }
      }
    }

    throw new RevealProofStorageError()
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
