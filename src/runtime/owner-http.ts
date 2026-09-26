import {
  hashOwnerCapability,
  isValidOwnerCapability,
  type OwnerCapability,
} from '../core/owner-capability'
import { isValidSecretId, type SecretRepository, type SecretStatus } from '../core/secret'
import { withSecretSecurityHeaders } from './security-headers'

function json(data: unknown, status: number): Response {
  return withSecretSecurityHeaders(Response.json(data, { status }))
}

function ownerCapability(request: Request): OwnerCapability | undefined {
  const authorization = request.headers.get('Authorization')
  if (!authorization?.startsWith('Bearer ')) {
    return undefined
  }

  const value = authorization.slice('Bearer '.length)
  return isValidOwnerCapability(value) ? value : undefined
}

function publicStatus(status: SecretStatus) {
  return {
    state: status.state,
    expiresAtMs: status.expiresAtMs,
  }
}

async function ownerKeyHash(request: Request): Promise<string | undefined> {
  const capability = ownerCapability(request)
  return capability ? await hashOwnerCapability(capability) : undefined
}

export async function ownerStatusResponse(
  request: Request,
  id: string,
  repository: SecretRepository,
  nowMs = Date.now(),
): Promise<Response> {
  if (!isValidSecretId(id)) {
    return json({ error: 'not_found' }, 404)
  }

  const hash = await ownerKeyHash(request)
  if (!hash) {
    return json({ error: 'not_found' }, 404)
  }

  const status = await repository.getStatus(id, hash, nowMs)
  return status ? json(publicStatus(status), 200) : json({ error: 'not_found' }, 404)
}

export async function ownerRevokeResponse(
  request: Request,
  id: string,
  repository: SecretRepository,
  nowMs = Date.now(),
): Promise<Response> {
  if (!isValidSecretId(id)) {
    return json({ error: 'not_found' }, 404)
  }

  const hash = await ownerKeyHash(request)
  if (!hash) {
    return json({ error: 'not_found' }, 404)
  }

  const result = await repository.revoke(id, hash, nowMs)
  if (result.kind === 'not_found') {
    return json({ error: 'not_found' }, 404)
  }

  const status = await repository.getStatus(id, hash, nowMs)
  return status ? json(publicStatus(status), 200) : json({ error: 'not_found' }, 404)
}
