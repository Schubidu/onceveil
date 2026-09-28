import type { SecretId } from './secret'

export const REVEAL_PROTECTION_ACTION = 'onceveil_reveal' as const
export const REVEAL_PROOF_TTL_MS = 60_000
export const REVEAL_VERIFICATION_TTL_MS = 5 * 60_000
export const MAX_ACTIVE_REVEAL_PROOFS_PER_SECRET = 3

export interface RevealProtectionContext {
  token?: string
  secretId: SecretId
  verificationId: string
  hostname: string
  remoteIp?: string
}

export type RevealProtectionResult =
  | { kind: 'verified' }
  | { kind: 'invalid' }
  | { kind: 'unavailable' }

export interface RevealProtectionVerifier {
  verify(context: RevealProtectionContext): Promise<RevealProtectionResult>
}

export interface RevealProof {
  value: string
  verificationId: string
  expiresAtMs: number
}

export interface RevealProofRepository {
  prepare(
    secretId: SecretId,
    authorization: string,
    verificationId: string,
    nowMs: number,
  ): Promise<RevealProof | undefined>
  hasPendingVerification(
    secretId: SecretId,
    verificationId: string,
    nowMs: number,
  ): Promise<boolean>
  verify(secretId: SecretId, verificationId: string, nowMs: number): Promise<boolean>
  consume(secretId: SecretId, proof: string, nowMs: number): Promise<boolean>
}
