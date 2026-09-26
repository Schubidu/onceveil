import {
  decodeEncryptedSecretPayload,
  encodeEncryptedSecretPayload,
  isEncryptedSecretPayload,
} from '../core/share-capability'
import { isValidSecretId, prepareSecretRecord, type SecretRepository } from '../core/secret'
import { withSecretSecurityHeaders } from './security-headers'

interface CreateRequestBody {
  payload: unknown
  ttlMs?: unknown
}

function json(data: unknown, status: number): Response {
  return withSecretSecurityHeaders(Response.json(data, { status }))
}

async function readCreateBody(request: Request): Promise<CreateRequestBody | undefined> {
  try {
    const value: unknown = await request.json()
    if (typeof value !== 'object' || value === null || !('payload' in value)) {
      return undefined
    }

    return value as CreateRequestBody
  } catch {
    return undefined
  }
}

export async function createSecretResponse(
  request: Request,
  repository: SecretRepository,
  nowMs = Date.now(),
): Promise<Response> {
  const body = await readCreateBody(request)
  if (!body || !isEncryptedSecretPayload(body.payload)) {
    return json({ error: 'invalid_request' }, 400)
  }

  const ttlMs =
    body.ttlMs === undefined || body.ttlMs === null || typeof body.ttlMs === 'number'
      ? body.ttlMs
      : Number.NaN

  const encoded = encodeEncryptedSecretPayload(body.payload)
  const prepared = prepareSecretRecord(body.payload.id, encoded, nowMs, ttlMs)
  if (!prepared.ok) {
    return json(
      { error: prepared.reason.toLowerCase() },
      prepared.reason === 'PAYLOAD_TOO_LARGE' ? 413 : 400,
    )
  }

  const result = await repository.create(prepared.record)
  if (result.kind === 'duplicate') {
    return json({ error: 'duplicate' }, 409)
  }

  return json({ id: prepared.record.id }, 201)
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
  if (!payload || payload.id !== id) {
    return json({ error: 'invalid_stored_payload' }, 500)
  }

  return json(payload, 200)
}
