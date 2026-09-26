import type { SecretId } from './secret'

export const REVEAL_PROTECTION_ACTION = 'onceveil_reveal' as const
export const REVEAL_PROOF_TTL_MS = 60_000

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
  expiresAtMs: number
}

export interface RevealProofRepository {
  issue(secretId: SecretId, nowMs: number): Promise<RevealProof>
  consume(secretId: SecretId, proof: string, nowMs: number): Promise<boolean>
}
