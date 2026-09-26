import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'

import {
  decryptSecret,
  InvalidShareCapabilityError,
  LegacyShareCapabilityError,
  revealAuthorizationFromFragment,
  takeShareFragment,
} from '../browser/secret-crypto'
import {
  discardRevealVerificationFragment,
  requestRevealProof,
  revealVerificationId,
} from '../browser/reveal-verification'
import { REVEAL_PROTECTION_ACTION } from '../core/reveal-protection'
import { isValidSecretId, type SecretId } from '../core/secret'

const TURNSTILE_SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

interface TurnstileApi {
  render(
    container: HTMLElement,
    options: {
      sitekey: string
      action: string
      cData: string
      callback(token: string): void
      'error-callback'(): void
      'expired-callback'(): void
    },
  ): string
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

interface TurnstileConfig {
  provider: 'turnstile'
  siteKey: string
  action: typeof REVEAL_PROTECTION_ACTION
}

export const Route = createFileRoute('/s/$id')({
  server: {
    handlers: {
      HEAD: async () => new Response(null, { status: 200 }),
    },
  },
  component: SecretLanding,
})

function SecretLanding() {
  const { id } = Route.useParams()
  const [verificationId, setVerificationId] = useState<string | null>()

  useEffect(() => {
    const candidate = revealVerificationId(window.location.search)
    if (candidate) {
      discardRevealVerificationFragment(window.location, window.history)
    }

    setVerificationId(candidate ?? null)
  }, [])

  if (verificationId === undefined) {
    return null
  }

  if (!isValidSecretId(id)) {
    return <SecretError message="This secret link is invalid." />
  }

  return verificationId ? (
    <TurnstileVerification id={id} verificationId={verificationId} />
  ) : (
    <SecretReveal id={id} />
  )
}

function SecretReveal({ id }: { id: SecretId }) {
  const fragment = useRef<string | undefined>(undefined)
  const [capabilityReady, setCapabilityReady] = useState(false)
  const [revealing, setRevealing] = useState(false)
  const [plaintext, setPlaintext] = useState<string>()
  const [error, setError] = useState<string>()

  useEffect(() => {
    fragment.current = takeShareFragment(window.location, window.history)
    setCapabilityReady(true)
  }, [])

  async function reveal() {
    if (!fragment.current || revealing || plaintext !== undefined) {
      return
    }

    setRevealing(true)
    setError(undefined)

    try {
      const proof = await requestRevealProof(id, revealAuthorizationFromFragment(fragment.current))
      const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Onceveil-Reveal': '1',
        },
        body: JSON.stringify({ proof }),
      })

      if (!response.ok) {
        setError(response.status === 410 ? 'This secret is no longer available.' : 'Reveal failed.')
        return
      }

      const payload: unknown = await response.json()
      const revealed = await decryptSecret(payload, fragment.current)
      fragment.current = undefined
      setPlaintext(revealed)
    } catch (cause) {
      setError(
        cause instanceof LegacyShareCapabilityError
          ? 'This link uses the previous share format and cannot be revealed after the security upgrade.'
          : cause instanceof InvalidShareCapabilityError
            ? 'The share capability is invalid or the encrypted payload was modified.'
            : 'Verification or reveal failed.',
      )
    } finally {
      setRevealing(false)
    }
  }

  return (
    <main className="shell">
      <section className="card" aria-labelledby="secret-title">
        <p className="eyebrow">One-time secret</p>
        <h1 id="secret-title">Onceveil</h1>

        {plaintext !== undefined ? (
          <pre className="secret-value">{plaintext}</pre>
        ) : (
          <>
            <p className="status">
              Opening this page does not reveal or consume the secret. Reveal requires a separate
              verification step and an explicit one-time action.
            </p>
            <button
              type="button"
              onClick={reveal}
              disabled={!capabilityReady || !fragment.current || revealing}
            >
              {revealing ? 'Verifying…' : 'Verify & reveal secret'}
            </button>
          </>
        )}

        {capabilityReady && !fragment.current && plaintext === undefined ? (
          <p className="error" role="alert">
            This link does not contain a usable decryption capability.
          </p>
        ) : null}

        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </main>
  )
}

function TurnstileVerification({ id, verificationId }: { id: SecretId; verificationId: string }) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [status, setStatus] = useState('Preparing verification…')
  const [error, setError] = useState<string>()

  useEffect(() => {
    let active = true
    let started = false
    let script: HTMLScriptElement | undefined
    const broadcast = new BroadcastChannel(`onceveil-reveal-${verificationId}`)

    function failVerification(message: string) {
      if (!active) {
        return
      }

      broadcast.postMessage({ type: 'onceveil-reveal-proof-error' })
      setError(message)
    }

    async function completeVerification(token: string) {
      try {
        const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Onceveil-Proof-Request': '1',
          },
          body: JSON.stringify({ token, verificationId }),
        })

        const body = (await response.json().catch(() => undefined)) as
          | Record<string, unknown>
          | undefined

        if (!active || !response.ok || body?.verified !== true) {
          const diagnostic =
            typeof body?.diagnostic === 'string' &&
            [
              'siteverify_rejected',
              'siteverify_unavailable',
              'hostname_mismatch',
              'action_mismatch',
              'cdata_mismatch',
              'proof_activation_failed',
            ].includes(body.diagnostic)
              ? ` (${body.diagnostic})`
              : ''
          failVerification(`Verification failed${diagnostic}. Close this window and try again.`)
          return
        }

        broadcast.postMessage({ type: 'onceveil-reveal-verified' })
        setStatus('Verified. Returning to the secret…')
        window.close()
      } catch {
        failVerification('Verification failed. Close this window and try again.')
      }
    }

    async function start() {
      try {
        const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
          headers: { 'X-Onceveil-Proof-Config': '1' },
        })
        const config = (await response.json().catch(() => undefined)) as
          | Partial<TurnstileConfig>
          | undefined

        if (
          !active ||
          !response.ok ||
          config?.provider !== 'turnstile' ||
          typeof config.siteKey !== 'string' ||
          config.action !== REVEAL_PROTECTION_ACTION
        ) {
          throw new Error('Reveal protection is unavailable')
        }

        script = document.createElement('script')
        script.src = TURNSTILE_SCRIPT_URL
        script.async = true
        script.defer = true
        script.onload = () => {
          if (!active || !containerRef.current || !window.turnstile) {
            failVerification('Verification failed to initialize.')
            return
          }

          setStatus('Complete the verification to continue.')
          window.turnstile.render(containerRef.current, {
            sitekey: config.siteKey as string,
            action: REVEAL_PROTECTION_ACTION,
            cData: id,
            callback: (token) => void completeVerification(token),
            'error-callback': () => failVerification('Verification failed. Try again.'),
            'expired-callback': () => failVerification('Verification expired. Try again.'),
          })
        }
        script.onerror = () => failVerification('Verification failed to load.')
        document.head.append(script)
      } catch {
        failVerification('Verification is unavailable.')
      }
    }

    broadcast.onmessage = (event: MessageEvent<unknown>) => {
      const message = event.data
      if (typeof message !== 'object' || message === null || !('type' in message)) {
        return
      }

      if ((message as { type?: unknown }).type === 'onceveil-reveal-prepared' && !started) {
        started = true
        void start()
        return
      }

      if ((message as { type?: unknown }).type === 'onceveil-reveal-proof-error') {
        setError('Verification could not be prepared. Close this window and try again.')
      }
    }

    broadcast.postMessage({ type: 'onceveil-reveal-verification-ready' })

    return () => {
      active = false
      script?.remove()
      broadcast.close()
    }
  }, [id, verificationId])

  return (
    <main className="shell">
      <section className="card" aria-labelledby="verify-title">
        <p className="eyebrow">Reveal verification</p>
        <h1 id="verify-title">Onceveil</h1>
        <p className="status">{status}</p>
        <div ref={containerRef} />
        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </main>
  )
}

function SecretError({ message }: { message: string }) {
  return (
    <main className="shell">
      <section className="card">
        <p className="error" role="alert">
          {message}
        </p>
      </section>
    </main>
  )
}
