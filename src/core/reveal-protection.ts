import type { SecretId } from './secret'

export const REVEAL_PROTECTION_ACTION = 'onceveil_reveal' as const
export const REVEAL_PROOF_TTL_MS = 60_000
export const REVEAL_VERIFICATION_TTL_MS = 5 * 60_000

export interface RevealChallengeContext {
  token: string
  secretId: SecretId
  hostname: string
  remoteIp?: string
}

export type RevealChallengeResult =
  | { kind: 'verified' }
  | { kind: 'invalid' }
  | { kind: 'unavailable' }

export interface RevealChallengeVerifier {
  verify(context: RevealChallengeContext): Promise<RevealChallengeResult>
}

export interface RevealProof {
  value: string
  verificationId: string
  expiresAtMs: number
}

export interface RevealProofRepository {
  prepare(secretId: SecretId, nowMs: number): Promise<RevealProof>
  verify(secretId: SecretId, verificationId: string, nowMs: number): Promise<boolean>
  consume(secretId: SecretId, proof: string, nowMs: number): Promise<boolean>
}
