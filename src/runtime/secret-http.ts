import {
  decodeEncryptedSecretPayload,
  encodeEncryptedSecretPayload,
  encryptedPayloadReplayKey,
  isEncryptedSecretPayload,
} from '../core/share-capability'
import {
  DEFAULT_SECRET_POLICY,
  generateSecretId,
  isValidSecretId,
  prepareSecretRecord,
  type SecretId,
  type SecretRepository,
} from '../core/secret'
import { withSecretSecurityHeaders } from './security-headers'

interface CreateRequestBody {
  payload: unknown
  ttlMs?: unknown
}

type CreateBodyReadResult =
  | { kind: 'ok'; body: CreateRequestBody }
  | { kind: 'invalid' }
  | { kind: 'too_large' }

export const MAX_CREATE_REQUEST_BYTES = DEFAULT_SECRET_POLICY.maxPayloadBytes + 2 * 1024
const PUBLIC_ID_ATTEMPTS = 3

function json(data: unknown, status: number): Response {
  return withSecretSecurityHeaders(Response.json(data, { status }))
}

async function readCreateBody(request: Request): Promise<CreateBodyReadResult> {
  const contentLength = request.headers.get('content-length')
  if (contentLength !== null) {
    const length = Number(contentLength)
    if (Number.isFinite(length) && length > MAX_CREATE_REQUEST_BYTES) {
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
      if (total > MAX_CREATE_REQUEST_BYTES) {
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
    if (typeof value !== 'object' || value === null || !('payload' in value)) {
      return { kind: 'invalid' }
    }

    return { kind: 'ok', body: value as CreateRequestBody }
  } catch {
    return { kind: 'invalid' }
  }
}

export async function createSecretResponse(
  request: Request,
  repository: SecretRepository,
  nowMs = Date.now(),
  generatePublicId: () => SecretId = generateSecretId,
): Promise<Response> {
  const bodyResult = await readCreateBody(request)
  if (bodyResult.kind === 'too_large') {
    return json({ error: 'payload_too_large' }, 413)
  }

  if (bodyResult.kind !== 'ok') {
    return json({ error: 'invalid_request' }, 400)
  }

  const body = bodyResult.body
  if (!isEncryptedSecretPayload(body.payload)) {
    return json({ error: 'invalid_request' }, 400)
  }

  const payload = body.payload
  const ttlMs = body.ttlMs === undefined || typeof body.ttlMs === 'number' ? body.ttlMs : Number.NaN

  const encoded = encodeEncryptedSecretPayload(payload)
  const replayKey = await encryptedPayloadReplayKey(payload)

  for (let attempt = 0; attempt < PUBLIC_ID_ATTEMPTS; attempt += 1) {
    const prepared = prepareSecretRecord(generatePublicId(), encoded, nowMs, ttlMs)
    if (!prepared.ok) {
      return json(
        { error: prepared.reason.toLowerCase() },
        prepared.reason === 'PAYLOAD_TOO_LARGE' ? 413 : 400,
      )
    }

    const result = await repository.create(prepared.record, replayKey)
    if (result.kind === 'created') {
      return json({ id: result.id }, 201)
    }

    if (result.kind === 'replayed') {
      return json({ id: result.id }, 200)
    }

    if (result.kind === 'replay_conflict') {
      return json({ error: 'replay_conflict' }, 409)
    }
  }

  return json({ error: 'id_allocation_failed' }, 503)
}

export async function revealSecretResponse(
  id: string,
  repository: SecretRepository,
  nowMs = Date.now(),
): Promise<Response> {
  if (!isValidSecretId(id)) {
    return json({ error: 'not_found' }, 404)
  }

  const result = await repository.consume(id, nowMs)
  if (result.kind === 'not_found') {
    return json({ error: 'not_found' }, 404)
  }

  if (result.kind === 'unavailable') {
    return json({ error: 'unavailable' }, 410)
  }

  const payload = decodeEncryptedSecretPayload(result.ciphertext)
  if (!payload) {
    return json({ error: 'invalid_stored_payload' }, 500)
  }

  return json(payload, 200)
}
