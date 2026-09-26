import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'

import { sharePath } from '../browser/secret-crypto'
import {
  encryptedShareForCreate,
  type PendingEncryptedCreate,
} from '../browser/secret-create-retry'
import { PROJECT_NAME, PROJECT_TAGLINE } from '../core/project'
import { isValidSecretId } from '../core/secret'

export const Route = createFileRoute('/')({
  component: Home,
})

function Home() {
  const [secret, setSecret] = useState('')
  const [shareUrl, setShareUrl] = useState<string>()
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string>()
  const [creating, setCreating] = useState(false)
  const [pendingCreate, setPendingCreate] = useState<PendingEncryptedCreate>()

  async function createSecret() {
    if (!secret || creating) {
      return
    }

    setCreating(true)
    setError(undefined)
    setShareUrl(undefined)
    setCopied(false)

    try {
      const pending = await encryptedShareForCreate(secret, pendingCreate)
      setPendingCreate(pending)

      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: pending.encrypted.payload }),
      })

      const body = (await response.json().catch(() => undefined)) as
        | Record<string, unknown>
        | undefined

      if (!response.ok) {
        let code = 'request_failed'
        if (typeof body?.error === 'string') {
          code = body.error
        }

        throw new Error(`store failed (${response.status} ${code})`)
      }

      const id = typeof body?.id === 'string' && isValidSecretId(body.id) ? body.id : undefined
      if (!id) {
        throw new Error('store failed (invalid_response)')
      }

      setShareUrl(`${window.location.origin}${sharePath(id, pending.encrypted.fragment)}`)
      setPendingCreate(undefined)
      setSecret('')
    } catch (cause) {
      setError(
        cause instanceof Error
          ? `The encrypted secret could not be stored: ${cause.message}`
          : 'The encrypted secret could not be stored.',
      )
    } finally {
      setCreating(false)
    }
  }

  async function copyShareUrl() {
    if (!shareUrl) {
      return
    }

    try {
      await navigator.clipboard.writeText(shareUrl)
      setCopied(true)
      setError(undefined)
    } catch {
      setCopied(false)
      setError('The one-time link could not be copied.')
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
            disabled={creating}
            onChange={(event) => {
              const value = event.target.value
              if (pendingCreate && pendingCreate.secret !== value) {
                setPendingCreate(undefined)
              }
              setSecret(value)
            }}
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
            <button
              className="copy-link"
              type="button"
              onClick={copyShareUrl}
              aria-label="Copy one-time link to clipboard"
            >
              <code>{shareUrl}</code>
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
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
