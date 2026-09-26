import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'

import { ownerPath } from '../browser/owner-capability'
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
  const [ownerUrl, setOwnerUrl] = useState<string>()
  const [copied, setCopied] = useState<'share' | 'owner'>()
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
    setOwnerUrl(undefined)
    setCopied(undefined)

    try {
      const pending = await encryptedShareForCreate(secret, pendingCreate)
      setPendingCreate(pending)

      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: pending.encrypted.payload,
          ownerKeyHash: pending.ownerCapabilityHash,
        }),
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
      setOwnerUrl(`${window.location.origin}${ownerPath(id, pending.ownerCapability)}`)
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

  function resetCreate() {
    setSecret('')
    setShareUrl(undefined)
    setOwnerUrl(undefined)
    setCopied(undefined)
    setError(undefined)
    setPendingCreate(undefined)
  }

  async function copyUrl(kind: 'share' | 'owner', value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(kind)
      setError(undefined)
    } catch {
      setCopied(undefined)
      setError('The link could not be copied.')
    }
  }

  return (
    <main className="shell">
      <section className="card" aria-labelledby="onceveil-title">
        <p className="eyebrow">Open source · early development</p>
        <h1 id="onceveil-title">{PROJECT_NAME}</h1>
        <p className="tagline">{PROJECT_TAGLINE}</p>

        {!shareUrl && !ownerUrl ? (
          <>
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
                autoComplete="off"
                spellCheck={false}
              />
            </label>

            <button type="button" onClick={createSecret} disabled={!secret || creating}>
              {creating ? 'Encrypting…' : 'Create one-time link'}
            </button>
          </>
        ) : null}

        {shareUrl ? (
          <div className="result" aria-live="polite">
            <strong>Share this link once:</strong>
            <button
              className="copy-link"
              type="button"
              onClick={() => void copyUrl('share', shareUrl)}
              aria-label="Copy one-time link to clipboard"
            >
              <code>{shareUrl}</code>
              <span>{copied === 'share' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        ) : null}

        {ownerUrl ? (
          <div className="result" aria-live="polite">
            <strong>Keep this owner link private:</strong>
            <button
              className="copy-link"
              type="button"
              onClick={() => void copyUrl('owner', ownerUrl)}
              aria-label="Copy owner link to clipboard"
            >
              <code>{ownerUrl}</code>
              <span>{copied === 'owner' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        ) : null}

        {shareUrl && ownerUrl ? (
          <button type="button" onClick={resetCreate}>
            Create another secret
          </button>
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
