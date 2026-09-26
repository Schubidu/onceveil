import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'

import {
  decryptSecret,
  InvalidShareCapabilityError,
  takeShareFragment,
} from '../browser/secret-crypto'

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
  const fragment = useRef<string>()
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
      const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
        method: 'POST',
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
        cause instanceof InvalidShareCapabilityError
          ? 'The share capability is invalid or the encrypted payload was modified.'
          : 'Reveal failed.',
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
              Opening this page does not reveal or consume the secret. Reveal is an explicit
              one-time action.
            </p>
            <button
              type="button"
              onClick={reveal}
              disabled={!capabilityReady || !fragment.current || revealing}
            >
              {revealing ? 'Revealing…' : 'Reveal secret'}
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
