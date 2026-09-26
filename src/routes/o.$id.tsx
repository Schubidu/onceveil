import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'

import { takeOwnerCapability } from '../browser/owner-capability'
import type { OwnerCapability } from '../core/owner-capability'
import { isValidSecretId, type SecretState } from '../core/secret'

interface OwnerStatus {
  state: SecretState
  expiresAtMs: number
}

async function requestOwnerStatus(
  id: string,
  method: 'GET' | 'DELETE',
  owner: OwnerCapability,
): Promise<OwnerStatus> {
  const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/owner`, {
    method,
    headers: {
      Authorization: `Bearer ${owner}`,
    },
  })

  const body = (await response.json().catch(() => undefined)) as Partial<OwnerStatus> | undefined
  if (
    !response.ok ||
    typeof body?.state !== 'string' ||
    !['AVAILABLE', 'CONSUMED', 'EXPIRED', 'REVOKED'].includes(body.state) ||
    typeof body.expiresAtMs !== 'number'
  ) {
    throw new Error('owner_operation_failed')
  }

  return body as OwnerStatus
}

export const Route = createFileRoute('/o/$id')({
  server: {
    handlers: {
      HEAD: async () => new Response(null, { status: 200 }),
    },
  },
  component: OwnerSecret,
})

function OwnerSecret() {
  const { id } = Route.useParams()
  const capability = useRef<OwnerCapability | undefined>(undefined)
  const generation = useRef(0)
  const [ready, setReady] = useState(false)
  const [status, setStatus] = useState<OwnerStatus>()
  const [error, setError] = useState<string>()
  const [revoking, setRevoking] = useState(false)

  useEffect(() => {
    let active = true

    function loadOwner() {
      const currentGeneration = ++generation.current
      capability.current = undefined
      setReady(false)
      setStatus(undefined)
      setError(undefined)
      setRevoking(false)

      const owner = takeOwnerCapability(window.location, window.history)

      if (!isValidSecretId(id)) {
        setError('This owner link is invalid.')
        setReady(true)
        return
      }

      if (!owner) {
        setError('This owner link does not contain a usable management capability.')
        setReady(true)
        return
      }

      capability.current = owner
      void requestOwnerStatus(id, 'GET', owner)
        .then((nextStatus) => {
          if (active && generation.current === currentGeneration) {
            setStatus(nextStatus)
          }
        })
        .catch(() => {
          if (active && generation.current === currentGeneration) {
            setError('Secret status could not be loaded.')
          }
        })
        .finally(() => {
          if (active && generation.current === currentGeneration) {
            setReady(true)
          }
        })
    }

    loadOwner()
    window.addEventListener('hashchange', loadOwner)

    return () => {
      active = false
      generation.current += 1
      window.removeEventListener('hashchange', loadOwner)
    }
  }, [id])

  async function revoke() {
    const owner = capability.current
    if (!owner || revoking || status?.state !== 'AVAILABLE') {
      return
    }

    const currentGeneration = generation.current
    setRevoking(true)
    setError(undefined)
    try {
      const nextStatus = await requestOwnerStatus(id, 'DELETE', owner)
      if (generation.current === currentGeneration) {
        setStatus(nextStatus)
      }
    } catch {
      if (generation.current === currentGeneration) {
        setError('The secret could not be revoked.')
      }
    } finally {
      if (generation.current === currentGeneration) {
        setRevoking(false)
      }
    }
  }

  return (
    <main className="shell">
      <section className="card" aria-labelledby="owner-title">
        <p className="eyebrow">Secret owner</p>
        <h1 id="owner-title">Onceveil</h1>

        {!ready ? <p className="status">Loading secret status…</p> : null}

        {status ? (
          <>
            <p className="status">
              Status: <strong>{status.state}</strong>
              <br />
              Expires: {new Date(status.expiresAtMs).toLocaleString()}
            </p>
            {status.state === 'AVAILABLE' ? (
              <button type="button" onClick={revoke} disabled={revoking}>
                {revoking ? 'Revoking…' : 'Revoke secret'}
              </button>
            ) : null}
          </>
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
