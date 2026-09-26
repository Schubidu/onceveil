import type { SecretId } from '../core/secret'

const VERIFICATION_BYTES = 16
const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/
const PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/
const REVEAL_AUTHORIZATION_PATTERN = /^[0-9a-f]{64}$/
const VERIFICATION_TIMEOUT_MS = 5 * 60 * 1000

export const REVEAL_VERIFICATION_WINDOW_FEATURES = 'popup,noopener,noreferrer,width=520,height=680'

export type RevealVerificationMessage =
  | { type: 'onceveil-reveal-verification-ready' }
  | { type: 'onceveil-reveal-prepared' }
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

function randomVerificationId(): string {
  const bytes = new Uint8Array(VERIFICATION_BYTES)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
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

async function prepareRevealProof(
  id: SecretId,
  authorization: string,
  verificationId: string,
): Promise<RevealProofPreparation> {
  const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Onceveil-Proof-Prepare': '1',
    },
    body: JSON.stringify({ authorization, verificationId }),
  })
  const body = (await response.json().catch(() => undefined)) as
    | Partial<RevealProofPreparation>
    | undefined

  if (
    !response.ok ||
    typeof body?.proof !== 'string' ||
    !PROOF_PATTERN.test(body.proof) ||
    body.verificationId !== verificationId
  ) {
    throw new Error('Reveal verification could not be prepared')
  }

  return {
    proof: body.proof,
    verificationId,
  }
}

export function requestRevealProof(id: SecretId, authorization: string): Promise<string> {
  if (!REVEAL_AUTHORIZATION_PATTERN.test(authorization)) {
    return Promise.reject(new Error('Invalid reveal authorization'))
  }

  const verificationId = randomVerificationId()
  const broadcast = new BroadcastChannel(`onceveil-reveal-${verificationId}`)
  const verificationUrl = revealVerificationUrl(id, verificationId, window.location.origin)

  return new Promise((resolve, reject) => {
    let proof: string | undefined
    let preparing = false
    let settled = false

    function finish(action: () => void) {
      if (settled) {
        return
      }

      settled = true
      window.clearTimeout(timeout)
      broadcast.close()
      action()
    }

    const timeout = window.setTimeout(() => {
      finish(() => reject(new Error('Reveal verification timed out')))
    }, VERIFICATION_TIMEOUT_MS)

    broadcast.onmessage = (event: MessageEvent<unknown>) => {
      const message = event.data
      if (typeof message !== 'object' || message === null || !('type' in message)) {
        return
      }

      const candidate = message as Partial<RevealVerificationMessage>
      if (
        candidate.type === 'onceveil-reveal-verification-ready' &&
        !preparing &&
        proof === undefined
      ) {
        preparing = true
        void prepareRevealProof(id, authorization, verificationId)
          .then((prepared) => {
            if (settled) {
              return
            }

            proof = prepared.proof
            broadcast.postMessage({
              type: 'onceveil-reveal-prepared',
            } satisfies RevealVerificationMessage)
          })
          .catch(() => {
            if (!settled) {
              broadcast.postMessage({
                type: 'onceveil-reveal-proof-error',
              } satisfies RevealVerificationMessage)
            }
            finish(() => reject(new Error('Reveal verification could not be prepared')))
          })
        return
      }

      if (candidate.type === 'onceveil-reveal-verified' && proof !== undefined) {
        finish(() => resolve(proof as string))
        return
      }

      if (candidate.type === 'onceveil-reveal-proof-error') {
        finish(() => reject(new Error('Reveal verification failed')))
      }
    }

    window.open(verificationUrl, '_blank', REVEAL_VERIFICATION_WINDOW_FEATURES)
  })
}
