import { REVEAL_PROTECTION_ACTION } from '../core/reveal-protection'
import type { SecretId } from '../core/secret'

const VERIFICATION_BYTES = 16
const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/
const PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/
const REVEAL_AUTHORIZATION_PATTERN = /^[0-9a-f]{64}$/
const VERIFICATION_TIMEOUT_MS = 5 * 60 * 1000
const VERIFICATION_READY_TIMEOUT_MS = 10 * 1000

export const REVEAL_VERIFICATION_WINDOW_FEATURES = 'popup,noopener,noreferrer,width=520,height=680'

export type RevealVerificationMessage =
  | { type: 'onceveil-reveal-verification-ready' }
  | { type: 'onceveil-reveal-prepared' }
  | { type: 'onceveil-reveal-verified' }
  | { type: 'onceveil-reveal-proof-error'; errorCode?: string }
  | { type: 'onceveil-reveal-config'; siteKey: string; action: string }
  | { type: 'onceveil-reveal-token'; token: string }

export type RevealVerificationWindowMessage = RevealVerificationMessage & {
  verificationId: string
}

export function isExpectedVerificationMessage(
  event: Pick<MessageEvent<unknown>, 'origin' | 'source' | 'data'>,
  expectedSource: MessageEventSource | null,
  expectedOrigin: string,
  verificationId: string,
): event is MessageEvent<RevealVerificationWindowMessage> {
  if (event.origin !== expectedOrigin || event.source !== expectedSource) {
    return false
  }

  const candidate = event.data as Partial<RevealVerificationWindowMessage> | null
  return candidate?.verificationId === verificationId
}

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

interface RevealProtectionConfig {
  provider: 'turnstile'
  siteKey: string
  action: typeof REVEAL_PROTECTION_ACTION
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
  parentOrigin?: string,
): string {
  if (!VERIFICATION_ID_PATTERN.test(verificationId)) {
    throw new TypeError('Invalid reveal verification id')
  }

  const url = new URL(`/s/${encodeURIComponent(id)}`, origin)
  url.searchParams.set('verify', 'turnstile')
  url.searchParams.set('verification', verificationId)
  if (parentOrigin) {
    url.searchParams.set('parent', parentOrigin)
  }
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

async function getRevealProtectionConfig(id: SecretId): Promise<RevealProtectionConfig> {
  const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
    headers: { 'X-Onceveil-Proof-Config': '1' },
  })
  const config = (await response.json().catch(() => undefined)) as
    | Partial<RevealProtectionConfig>
    | undefined

  if (
    !response.ok ||
    config?.provider !== 'turnstile' ||
    typeof config.siteKey !== 'string' ||
    config.action !== REVEAL_PROTECTION_ACTION
  ) {
    throw new Error('Reveal protection is unavailable')
  }

  return {
    provider: 'turnstile',
    siteKey: config.siteKey,
    action: REVEAL_PROTECTION_ACTION,
  }
}

async function verifyRevealToken(
  id: SecretId,
  verificationId: string,
  token: string,
): Promise<void> {
  const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Onceveil-Proof-Request': '1',
    },
    body: JSON.stringify({ token, verificationId }),
  })
  const body = (await response.json().catch(() => undefined)) as Record<string, unknown> | undefined

  if (!response.ok || body?.verified !== true) {
    throw new Error('Reveal verification failed')
  }
}

function requestRevealProofPopup(id: SecretId, authorization: string): Promise<string> {
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
      window.clearTimeout(readyTimeout)
      broadcast.close()
      action()
    }

    const timeout = window.setTimeout(() => {
      finish(() => reject(new Error('Reveal verification timed out')))
    }, VERIFICATION_TIMEOUT_MS)
    const readyTimeout = window.setTimeout(() => {
      finish(() => reject(new Error('Reveal verification window did not start')))
    }, VERIFICATION_READY_TIMEOUT_MS)

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
        window.clearTimeout(readyTimeout)
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

function requestEmbeddedRevealProof(id: SecretId, authorization: string): Promise<string> {
  const verificationId = randomVerificationId()
  const verificationUrl = revealVerificationUrl(
    id,
    verificationId,
    window.location.origin,
    window.location.origin,
  )
  const dialog = document.createElement('dialog')
  const iframe = document.createElement('iframe')
  const fallback = document.createElement('button')
  const status = document.createElement('p')

  dialog.className = 'verification-dialog'
  dialog.setAttribute('aria-label', 'Reveal verification')

  iframe.className = 'verification-frame'
  iframe.title = 'Reveal verification'
  iframe.src = verificationUrl
  iframe.referrerPolicy = 'no-referrer'
  iframe.sandbox.add('allow-scripts', 'allow-forms', 'allow-popups')
  iframe.hidden = true

  status.className = 'verification-status'
  status.textContent = 'Preparing verification…'

  fallback.type = 'button'
  fallback.className = 'verification-fallback'
  fallback.textContent = 'Open verification in new window'
  fallback.hidden = true

  dialog.append(iframe, status, fallback)
  document.body.append(dialog)

  return new Promise((resolve, reject) => {
    let proof: string | undefined
    let preparing = false
    let verifying = false
    let settled = false
    let fallbackStarted = false

    const timeout = window.setTimeout(() => {
      finish(() => reject(new Error('Reveal verification timed out')))
    }, VERIFICATION_TIMEOUT_MS)
    const readyTimeout = window.setTimeout(() => {
      status.textContent = 'Embedded verification did not start.'
      fallback.hidden = false
    }, VERIFICATION_READY_TIMEOUT_MS)

    function cleanupEmbedded() {
      window.clearTimeout(timeout)
      window.clearTimeout(readyTimeout)
      window.removeEventListener('message', onMessage)
      dialog.removeEventListener('cancel', onCancel)
      fallback.removeEventListener('click', startFallback)
      if (dialog.open) {
        dialog.close()
      }
      dialog.remove()
    }

    function finish(action: () => void) {
      if (settled) {
        return
      }

      settled = true
      cleanupEmbedded()
      action()
    }

    function failEmbedded(message: string) {
      if (settled || fallbackStarted) {
        return
      }

      status.textContent = message
      iframe.hidden = true
      fallback.hidden = false
    }

    function startFallback() {
      if (settled || fallbackStarted) {
        return
      }

      fallbackStarted = true
      cleanupEmbedded()
      void requestRevealProofPopup(id, authorization).then(
        (popupProof) => {
          if (!settled) {
            settled = true
            resolve(popupProof)
          }
        },
        (cause) => {
          if (!settled) {
            settled = true
            reject(cause)
          }
        },
      )
    }

    function onCancel(event: Event) {
      event.preventDefault()
      finish(() => reject(new Error('Reveal verification cancelled')))
    }

    function postToVerification(message: RevealVerificationMessage) {
      iframe.contentWindow?.postMessage(
        {
          ...message,
          verificationId,
        } satisfies RevealVerificationWindowMessage,
        '*',
      )
    }

    function onMessage(event: MessageEvent<unknown>) {
      if (!isExpectedVerificationMessage(event, iframe.contentWindow, 'null', verificationId)) {
        return
      }

      const candidate = event.data

      if (
        candidate.type === 'onceveil-reveal-verification-ready' &&
        !preparing &&
        proof === undefined
      ) {
        window.clearTimeout(readyTimeout)
        preparing = true
        void prepareRevealProof(id, authorization, verificationId)
          .then(async (prepared) => {
            if (settled || fallbackStarted) {
              return
            }

            proof = prepared.proof
            const config = await getRevealProtectionConfig(id)
            if (settled || fallbackStarted) {
              return
            }

            status.textContent = 'Complete verification to reveal the secret.'
            iframe.hidden = false
            postToVerification({
              type: 'onceveil-reveal-config',
              siteKey: config.siteKey,
              action: config.action,
            })
          })
          .catch(() => {
            failEmbedded(
              'Embedded verification could not be prepared. Open verification in a new window instead.',
            )
          })
        return
      }

      if (candidate.type === 'onceveil-reveal-token' && proof !== undefined && !verifying) {
        if (typeof candidate.token !== 'string' || candidate.token.length === 0) {
          failEmbedded('Embedded verification failed. Open verification in a new window instead.')
          return
        }

        verifying = true
        void verifyRevealToken(id, verificationId, candidate.token).then(
          () => {
            if (!settled && !fallbackStarted && proof !== undefined) {
              finish(() => resolve(proof as string))
            }
          },
          () => {
            verifying = false
            failEmbedded('Embedded verification failed. Open verification in a new window instead.')
          },
        )
        return
      }

      if (candidate.type === 'onceveil-reveal-proof-error') {
        const errorCode =
          typeof candidate.errorCode === 'string' && candidate.errorCode
            ? ` (Turnstile ${candidate.errorCode})`
            : ''
        failEmbedded(
          `Embedded verification failed${errorCode}. Open verification in a new window instead.`,
        )
      }
    }

    window.addEventListener('message', onMessage)
    dialog.addEventListener('cancel', onCancel)
    fallback.addEventListener('click', startFallback)

    try {
      dialog.showModal()
    } catch {
      startFallback()
    }
  })
}

export function requestRevealProof(id: SecretId, authorization: string): Promise<string> {
  if (!REVEAL_AUTHORIZATION_PATTERN.test(authorization)) {
    return Promise.reject(new Error('Invalid reveal authorization'))
  }

  const supportsDialog =
    typeof HTMLDialogElement !== 'undefined' &&
    typeof document.createElement('dialog').showModal === 'function'

  return supportsDialog
    ? requestEmbeddedRevealProof(id, authorization)
    : requestRevealProofPopup(id, authorization)
}
