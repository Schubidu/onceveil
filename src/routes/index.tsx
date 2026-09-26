import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'

import { encryptSecret } from '../browser/secret-crypto'
import { PROJECT_NAME, PROJECT_TAGLINE } from '../core/project'

export const Route = createFileRoute('/')({
  component: Home,
})

function Home() {
  const [secret, setSecret] = useState('')
  const [shareUrl, setShareUrl] = useState<string>()
  const [error, setError] = useState<string>()
  const [creating, setCreating] = useState(false)

  async function createSecret() {
    if (!secret || creating) {
      return
    }

    setCreating(true)
    setError(undefined)
    setShareUrl(undefined)

    try {
      const encrypted = await encryptSecret(secret)
      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      })

      if (!response.ok) {
        throw new Error('create failed')
      }

      setShareUrl(`${window.location.origin}${encrypted.path}`)
      setSecret('')
    } catch {
      setError('The encrypted secret could not be stored.')
    } finally {
      setCreating(false)
    }
  }

  return (
    <main className="shell">
      <section className="card" aria-labelledby="onceveil-title">
        <p className="eyebrow">Open source · early development</p>
        <h1 id="onceveil-title">{PROJECT_NAME}</h1>
        <p className="tagline">{PROJECT_TAGLINE}</p>

        <label className="field">
          <span>Secret</span>
          <textarea
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            rows={7}
            autoComplete="off"
            spellCheck={false}
          />
        </label>

        <button type="button" onClick={createSecret} disabled={!secret || creating}>
          {creating ? 'Encrypting…' : 'Create one-time link'}
        </button>

        {shareUrl ? (
          <div className="result" aria-live="polite">
            <strong>Share this link once:</strong>
            <code>{shareUrl}</code>
          </div>
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
