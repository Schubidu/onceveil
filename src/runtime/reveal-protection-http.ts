import type { RevealChallengeVerifier, RevealProofRepository } from '../core/reveal-protection'
import type { SecretId, SecretRepository } from '../core/secret'
import { revealSecretResponse } from './secret-http'
import { withSecretSecurityHeaders } from './security-headers'

const MAX_PROTECTION_REQUEST_BYTES = 4 * 1024

interface ProtectionRequestBody {
  token?: unknown
  proof?: unknown
}

type ProtectionBodyResult =
  | { kind: 'ok'; body: ProtectionRequestBody }
  | { kind: 'invalid' }
  | { kind: 'too_large' }

function json(data: unknown, status: number): Response {
  return withSecretSecurityHeaders(Response.json(data, { status }))
}

async function readProtectionBody(request: Request): Promise<ProtectionBodyResult> {
  const contentLength = request.headers.get('content-length')
  if (contentLength !== null) {
    const length = Number(contentLength)
    if (Number.isFinite(length) && length > MAX_PROTECTION_REQUEST_BYTES) {
      return { kind: 'too_large' }
    }
  }

  if (!request.body) {
    return { kind: 'invalid' }
  }

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) {
        break
      }

      total += value.byteLength
      if (total > MAX_PROTECTION_REQUEST_BYTES) {
        await reader.cancel().catch(() => undefined)
        return { kind: 'too_large' }
      }

      chunks.push(value)
    }

    const bytes = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }

    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (typeof value !== 'object' || value === null) {
      return { kind: 'invalid' }
    }

    return { kind: 'ok', body: value as ProtectionRequestBody }
  } catch {
    return { kind: 'invalid' }
  }
}

export async function issueRevealProofResponse(
  request: Request,
  secretId: SecretId,
  verifier: RevealChallengeVerifier,
  proofs: RevealProofRepository,
  nowMs = Date.now(),
): Promise<Response> {
  const bodyResult = await readProtectionBody(request)
  if (bodyResult.kind === 'too_large') {
    return json({ error: 'invalid_verification' }, 400)
  }

  const token = bodyResult.kind === 'ok' ? bodyResult.body.token : undefined
  if (typeof token !== 'string') {
    return json({ error: 'invalid_verification' }, 400)
  }

  const verification = await verifier.verify({
    token,
    secretId,
    hostname: new URL(request.url).hostname,
    remoteIp: request.headers.get('CF-Connecting-IP') ?? undefined,
  })

  if (verification.kind === 'unavailable') {
    return json({ error: 'verification_unavailable' }, 503)
  }

  if (verification.kind !== 'verified') {
    return json({ error: 'verification_failed' }, 403)
  }

  const proof = await proofs.issue(secretId, nowMs)
  return json({ proof: proof.value, expiresAtMs: proof.expiresAtMs }, 201)
}

export async function consumeRevealProofResponse(
  request: Request,
  secretId: SecretId,
  proofs: RevealProofRepository,
  nowMs = Date.now(),
): Promise<Response | undefined> {
  const bodyResult = await readProtectionBody(request)
  const proof = bodyResult.kind === 'ok' ? bodyResult.body.proof : undefined
  if (typeof proof !== 'string') {
    return json({ error: 'reveal_protection_required' }, 403)
  }

  if (!(await proofs.consume(secretId, proof, nowMs))) {
    return json({ error: 'reveal_protection_required' }, 403)
  }

  return undefined
}

export async function protectedRevealResponse(
  request: Request,
  secretId: SecretId,
  proofs: RevealProofRepository,
  secrets: SecretRepository,
  nowMs = Date.now(),
): Promise<Response> {
  const proofFailure = await consumeRevealProofResponse(request, secretId, proofs, nowMs)
  if (proofFailure) {
    return proofFailure
  }

  return revealSecretResponse(secretId, secrets, nowMs)
}
