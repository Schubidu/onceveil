import type {
  RevealProtectionContext,
  RevealProtectionResult,
  RevealProtectionVerifier,
} from '../core/reveal-protection'

export class NoopRevealProtection implements RevealProtectionVerifier {
  async verify(_context: RevealProtectionContext): Promise<RevealProtectionResult> {
    return { kind: 'verified' }
  }
}
