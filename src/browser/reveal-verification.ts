import type { SecretId } from '../core/secret'

const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/
const PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/
const VERIFICATION_TIMEOUT_MS = 5 * 60 * 1000

export const REVEAL_VERIFICATION_WINDOW_FEATURES = 'popup,noopener,noreferrer,width=520,height=680'

export type RevealVerificationMessage =
  | { type: 'onceveil-reveal-verified' }
  | { type: 'onceveil-reveal-proof-error' }

export interface RevealVerificationLocation {
  hash: string
  pathname: string
  search: string
}

export interface RevealVerificationHistory {
  state: unknown
  replaceState(data: unknown, unused: string, url?: string | URL | null): void
}

interface RevealProofPreparation {
  proof: string
  verificationId: string
}

export function revealVerificationUrl(
  id: SecretId,
  verificationId: string,
  origin: string,
): string {
  if (!VERIFICATION_ID_PATTERN.test(verificationId)) {
    throw new TypeError('Invalid reveal verification id')
  }

  const url = new URL(`/s/${encodeURIComponent(id)}`, origin)
  url.searchParams.set('verify', 'turnstile')
  url.searchParams.set('verification', verificationId)
  return url.toString()
}

export function discardRevealVerificationFragment(
  location: RevealVerificationLocation,
  history: RevealVerificationHistory,
): void {
  if (!location.hash) {
    return
  }

  history.replaceState(history.state, '', `${location.pathname}${location.search}`)
}

export function revealVerificationId(search: string): string | undefined {
  const params = new URLSearchParams(search)
  const verificationId = params.get('verification')
  return params.get('verify') === 'turnstile' &&
    verificationId &&
    VERIFICATION_ID_PATTERN.test(verificationId)
    ? verificationId
    : undefined
}

export function publishRevealVerificationMessage(
  verificationId: string,
  message: RevealVerificationMessage,
): void {
  if (!VERIFICATION_ID_PATTERN.test(verificationId)) {
    return
  }

  const broadcast = new BroadcastChannel(`onceveil-reveal-${verificationId}`)
  broadcast.postMessage(message)
  broadcast.close()
}

async function prepareRevealProof(id: SecretId): Promise<RevealProofPreparation> {
  const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
    method: 'POST',
    headers: {
      'X-Onceveil-Proof-Prepare': '1',
    },
  })
  const body = (await response.json().catch(() => undefined)) as
    | Partial<RevealProofPreparation>
    | undefined

  if (
    !response.ok ||
    typeof body?.proof !== 'string' ||
    !PROOF_PATTERN.test(body.proof) ||
    typeof body.verificationId !== 'string' ||
    !VERIFICATION_ID_PATTERN.test(body.verificationId)
  ) {
    throw new Error('Reveal verification could not be prepared')
  }

  return {
    proof: body.proof,
    verificationId: body.verificationId,
  }
}

export async function requestRevealProof(id: SecretId): Promise<string> {
  const { proof, verificationId } = await prepareRevealProof(id)
  const broadcast = new BroadcastChannel(`onceveil-reveal-${verificationId}`)
  const verificationUrl = revealVerificationUrl(id, verificationId, window.location.origin)

  window.open(verificationUrl, '_blank', REVEAL_VERIFICATION_WINDOW_FEATURES)

  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      broadcast.close()
      reject(new Error('Reveal verification timed out'))
    }, VERIFICATION_TIMEOUT_MS)

    broadcast.onmessage = (event: MessageEvent<unknown>) => {
      const message = event.data
      if (typeof message !== 'object' || message === null || !('type' in message)) {
        return
      }

      const candidate = message as Partial<RevealVerificationMessage>
      if (candidate.type === 'onceveil-reveal-verified') {
        window.clearTimeout(timeout)
        broadcast.close()
        resolve(proof)
        return
      }

      if (candidate.type === 'onceveil-reveal-proof-error') {
        window.clearTimeout(timeout)
        broadcast.close()
        reject(new Error('Reveal verification failed'))
      }
    }
  })
}
