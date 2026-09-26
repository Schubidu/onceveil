import type { SecretId } from './secret'

export const REVEAL_PROTECTION_ACTION = 'onceveil_reveal' as const
export const REVEAL_PROOF_TTL_MS = 60_000
export const REVEAL_VERIFICATION_TTL_MS = 5 * 60_000
export const MAX_ACTIVE_REVEAL_PROOFS_PER_SECRET = 3

export interface RevealChallengeContext {
  token: string
  secretId: SecretId
  hostname: string
  remoteIp?: string
}

export type RevealChallengeDiagnostic =
  | 'siteverify_rejected'
  | 'siteverify_fetch_failed'
  | 'siteverify_http_error'
  | 'siteverify_invalid_response'
  | 'hostname_mismatch'
  | 'action_mismatch'
  | 'cdata_mismatch'

export type RevealChallengeResult =
  | { kind: 'verified' }
  | { kind: 'invalid'; diagnostic?: RevealChallengeDiagnostic }
  | { kind: 'unavailable'; diagnostic?: RevealChallengeDiagnostic }

export interface RevealChallengeVerifier {
  verify(context: RevealChallengeContext): Promise<RevealChallengeResult>
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
  verify(secretId: SecretId, verificationId: string, nowMs: number): Promise<boolean>
  consume(secretId: SecretId, proof: string, nowMs: number): Promise<boolean>
}
