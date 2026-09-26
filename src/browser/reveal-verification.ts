import type { SecretId } from '../core/secret'

const CHANNEL_BYTES = 16
const CHANNEL_PATTERN = /^[0-9a-f]{32}$/
const PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/
const VERIFICATION_TIMEOUT_MS = 5 * 60 * 1000

export const REVEAL_VERIFICATION_WINDOW_FEATURES =
  'popup,noopener,noreferrer,width=520,height=680'

export type RevealVerificationMessage =
  | { type: 'onceveil-reveal-proof'; proof: string }
  | { type: 'onceveil-reveal-proof-error' }

function randomChannel(): string {
  const bytes = new Uint8Array(CHANNEL_BYTES)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function revealVerificationUrl(id: SecretId, channel: string, origin: string): string {
  if (!CHANNEL_PATTERN.test(channel)) {
    throw new TypeError('Invalid reveal verification channel')
  }

  const url = new URL(`/s/${encodeURIComponent(id)}`, origin)
  url.searchParams.set('verify', 'turnstile')
  url.searchParams.set('channel', channel)
  return url.toString()
}

export function revealVerificationChannel(search: string): string | undefined {
  const params = new URLSearchParams(search)
  const channel = params.get('channel')
  return params.get('verify') === 'turnstile' && channel && CHANNEL_PATTERN.test(channel)
    ? channel
    : undefined
}

export function publishRevealVerificationMessage(
  channel: string,
  message: RevealVerificationMessage,
): void {
  if (!CHANNEL_PATTERN.test(channel)) {
    return
  }

  const broadcast = new BroadcastChannel(`onceveil-reveal-${channel}`)
  broadcast.postMessage(message)
  broadcast.close()
}

export function requestRevealProof(id: SecretId): Promise<string> {
  const channel = randomChannel()
  const broadcast = new BroadcastChannel(`onceveil-reveal-${channel}`)
  const verificationUrl = revealVerificationUrl(id, channel, window.location.origin)

  window.open(
    verificationUrl,
    '_blank',
    REVEAL_VERIFICATION_WINDOW_FEATURES,
  )

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

      const candidate = message as Partial<RevealVerificationMessage> & { proof?: unknown }
      if (
        candidate.type === 'onceveil-reveal-proof' &&
        typeof candidate.proof === 'string' &&
        PROOF_PATTERN.test(candidate.proof)
      ) {
        window.clearTimeout(timeout)
        broadcast.close()
        resolve(candidate.proof)
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
