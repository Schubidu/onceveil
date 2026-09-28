import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'

import { BrandHeading } from '../browser/branding'
import { validOnceveilShareUrl, takeMcpHandoffToken } from '../browser/mcp-handoff'
import { ownerPath } from '../browser/owner-capability'
import { sharePath } from '../browser/secret-crypto'
import {
  encryptedShareForCreate,
  type PendingEncryptedCreate,
} from '../browser/secret-create-retry'
import type { McpHandoffAction, McpHandoffToken } from '../core/mcp-handoff'
import { isValidSecretId, type SecretId } from '../core/secret'

interface CreatedSecret {
  id: SecretId
  ownerKeyHash: string
  shareUrl: string
  ownerUrl: string
}

export const Route = createFileRoute('/mcp/handoff/$flowId')({
  server: {
    handlers: {
      HEAD: async () => new Response(null, { status: 200 }),
    },
  },
  component: McpBrowserHandoff,
})

function McpBrowserHandoff() {
  const { flowId } = Route.useParams()
  const token = useRef<McpHandoffToken | undefined>(undefined)
  const [action, setAction] = useState<McpHandoffAction>()
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string>()

  useEffect(() => {
    let active = true
    const handoffToken = takeMcpHandoffToken(window.location, window.history)
    token.current = handoffToken

    if (!handoffToken) {
      setError('This browser handoff link is invalid or incomplete.')
      setReady(true)
      return
    }

    void fetch(`/api/mcp/handoffs/${encodeURIComponent(flowId)}`, {
      headers: { Authorization: `Bearer ${handoffToken}` },
    })
      .then(async (response) => {
        const body = (await response.json().catch(() => undefined)) as
          | Record<string, unknown>
          | undefined
        if (
          !response.ok ||
          (body?.action !== 'create' && body?.action !== 'reveal')
        ) {
          throw new Error('handoff_unavailable')
        }
        return body.action
      })
      .then((nextAction) => {
        if (active) {
          setAction(nextAction)
        }
      })
      .catch(() => {
        if (active) {
          setError('This browser handoff is unavailable or expired.')
        }
      })
      .finally(() => {
        if (active) {
          setReady(true)
        }
      })

    return () => {
      active = false
      token.current = undefined
    }
  }, [flowId])

  if (!ready) {
    return <HandoffFrame status="Loading secure browser handoff…" />
  }

  if (!token.current || !action) {
    return <HandoffFrame error={error ?? 'This browser handoff is unavailable.'} />
  }

  return action === 'create' ? (
    <CreateHandoff flowId={flowId} token={token.current} />
  ) : (
    <RevealHandoff flowId={flowId} token={token.current} />
  )
}

function HandoffFrame({
  children,
  status,
  error,
}: Readonly<{
  children?: React.ReactNode
  status?: string
  error?: string
}>) {
  return (
    <main className="shell">
      <section className="card" aria-labelledby="mcp-handoff-title">
        <p className="eyebrow">Secure browser handoff</p>
        <BrandHeading id="mcp-handoff-title" />
        {status ? <p className="status">{status}</p> : null}
        {children}
        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </main>
  )
}

function CreateHandoff({
  flowId,
  token,
}: Readonly<{ flowId: string; token: McpHandoffToken }>) {
  const [secret, setSecret] = useState('')
  const [pending, setPending] = useState<PendingEncryptedCreate>()
  const [created, setCreated] = useState<CreatedSecret>()
  const [creating, setCreating] = useState(false)
  const [completed, setCompleted] = useState(false)
  const [copied, setCopied] = useState<'share' | 'owner'>()
  const [error, setError] = useState<string>()

  async function completeHandoff(value: CreatedSecret): Promise<boolean> {
    const response = await fetch(`/api/mcp/handoffs/${encodeURIComponent(flowId)}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        secretId: value.id,
        ownerKeyHash: value.ownerKeyHash,
      }),
    })

    if (!response.ok) {
      setError(
        'The secret was created, but the MCP handoff could not be finalized. Keep both links and retry the handoff.',
      )
      return false
    }

    setCompleted(true)
    setError(undefined)
    return true
  }

  async function createSecret() {
    if (!secret || creating || created) {
      return
    }

    setCreating(true)
    setError(undefined)

    try {
      const encrypted = await encryptedShareForCreate(secret, pending)
      setPending(encrypted)

      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: encrypted.encrypted.payload,
          ownerKeyHash: encrypted.ownerCapabilityHash,
        }),
      })
      const body = (await response.json().catch(() => undefined)) as
        | Record<string, unknown>
        | undefined
      if (!response.ok || typeof body?.id !== 'string' || !isValidSecretId(body.id)) {
        throw new Error('create_failed')
      }

      const value: CreatedSecret = {
        id: body.id,
        ownerKeyHash: encrypted.ownerCapabilityHash,
        shareUrl: `${window.location.origin}${sharePath(body.id, encrypted.encrypted.fragment)}`,
        ownerUrl: `${window.location.origin}${ownerPath(body.id, encrypted.ownerCapability)}`,
      }
      setCreated(value)
      setSecret('')
      setPending(undefined)
      await completeHandoff(value)
    } catch {
      setError('The encrypted secret could not be created. You can retry safely.')
    } finally {
      setCreating(false)
    }
  }

  async function copy(kind: 'share' | 'owner', value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(kind)
      setError(undefined)
    } catch {
      setError('The link could not be copied.')
    }
  }

  return (
    <HandoffFrame error={error}>
      {!created ? (
        <>
          <p className="status">
            Enter the secret here. Encryption happens in this browser before the encrypted payload
            is sent to Onceveil. The secret text is never sent through MCP.
          </p>
          <label className="field">
            <span>Secret</span>
            <textarea
              value={secret}
              disabled={creating}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                const value = event.target.value
                if (pending && pending.secret !== value) {
                  setPending(undefined)
                }
                setSecret(value)
              }}
            />
          </label>
          <button type="button" disabled={!secret || creating} onClick={() => void createSecret()}>
            {creating ? 'Encrypting…' : 'Create one-time link'}
          </button>
        </>
      ) : (
        <>
          <p className="status">
            {completed
              ? 'Creation is complete. Only this browser receives the share and owner links.'
              : 'The secret was created. Keep both links while the MCP handoff is retried.'}
          </p>
          <div className="result">
            <strong>Share this link once:</strong>
            <button
              className="copy-link"
              type="button"
              onClick={() => void copy('share', created.shareUrl)}
            >
              <code>{created.shareUrl}</code>
              <span>{copied === 'share' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="result">
            <strong>Keep this owner link private:</strong>
            <button
              className="copy-link"
              type="button"
              onClick={() => void copy('owner', created.ownerUrl)}
            >
              <code>{created.ownerUrl}</code>
              <span>{copied === 'owner' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          {!completed ? (
            <button type="button" onClick={() => void completeHandoff(created)}>
              Retry MCP handoff
            </button>
          ) : null}
        </>
      )}
    </HandoffFrame>
  )
}

function RevealHandoff({
  flowId,
  token,
}: Readonly<{ flowId: string; token: McpHandoffToken }>) {
  const [shareUrl, setShareUrl] = useState('')
  const [opening, setOpening] = useState(false)
  const [error, setError] = useState<string>()

  async function openReveal() {
    if (!shareUrl || opening) {
      return
    }

    const target = validOnceveilShareUrl(shareUrl, window.location.origin)
    if (!target) {
      setError('Paste a valid share link for this Onceveil deployment.')
      return
    }

    setOpening(true)
    setError(undefined)
    try {
      const response = await fetch(`/api/mcp/handoffs/${encodeURIComponent(flowId)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) {
        throw new Error('handoff_failed')
      }

      window.location.assign(target)
    } catch {
      setError('The browser handoff could not be finalized. Try again.')
      setOpening(false)
    }
  }

  return (
    <HandoffFrame error={error}>
      <p className="status">
        Paste the complete Onceveil share link here. The link and its decryption capability remain
        in this browser and are never returned to MCP.
      </p>
      <label className="field">
        <span>Share link</span>
        <textarea
          value={shareUrl}
          disabled={opening}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setShareUrl(event.target.value.trim())}
        />
      </label>
      <button type="button" disabled={!shareUrl || opening} onClick={() => void openReveal()}>
        {opening ? 'Opening reveal…' : 'Continue to protected reveal'}
      </button>
    </HandoffFrame>
  )
}
