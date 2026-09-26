import { describe, expect, it } from 'vitest'

import { hashOwnerCapability, type OwnerCapability } from '../src/core/owner-capability'
import type {
  CreateResult,
  PreparedSecretRecord,
  RevokeResult,
  SecretId,
  SecretRepository,
  SecretStatus,
} from '../src/core/secret'
import { ownerRevokeResponse, ownerStatusResponse } from '../src/runtime/owner-http'

const ID = '0123456789abcdef0123456789abcdef' as SecretId
const CAPABILITY = 'a'.repeat(64) as OwnerCapability

class OwnerTestRepository implements SecretRepository {
  constructor(
    private readonly expectedHash: string,
    private state: SecretStatus['state'] = 'AVAILABLE',
  ) {}

  async create(
    _record: PreparedSecretRecord,
    _replayKey: string,
    _ownerKeyHash: string,
  ): Promise<CreateResult> {
    throw new Error('not used')
  }

  async consume() {
    return { kind: 'not_found' } as const
  }

  async revoke(
    id: SecretId,
    ownerKeyHash: string,
    _nowMs: number,
  ): Promise<RevokeResult | { kind: 'not_found' }> {
    if (id !== ID || ownerKeyHash !== this.expectedHash) {
      return { kind: 'not_found' }
    }

    if (this.state === 'AVAILABLE') {
      this.state = 'REVOKED'
      return {
        kind: 'revoked',
        status: this.status(),
      }
    }

    return {
      kind: 'unavailable',
      state: this.state as Exclude<SecretStatus['state'], 'AVAILABLE'>,
    }
  }

  async getStatus(
    id: SecretId,
    ownerKeyHash: string,
    _nowMs: number,
  ): Promise<SecretStatus | undefined> {
    return id === ID && ownerKeyHash === this.expectedHash ? this.status() : undefined
  }

  private status(): SecretStatus {
    return {
      id: ID,
      createdAtMs: 1_000,
      expiresAtMs: 2_000,
      state: this.state,
    }
  }
}

describe('owner HTTP boundary', () => {
  it('returns only minimal lifecycle metadata for the matching capability', async () => {
    const hash = await hashOwnerCapability(CAPABILITY)
    const repository = new OwnerTestRepository(hash)

    const response = await ownerStatusResponse(
      new Request(`https://onceveil.test/api/secrets/${ID}/owner`, {
        headers: { Authorization: `Bearer ${CAPABILITY}` },
      }),
      ID,
      repository,
      1_100,
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({
      state: 'AVAILABLE',
      expiresAtMs: 2_000,
    })
  })

  it('does not distinguish a wrong owner capability from an unknown secret', async () => {
    const hash = await hashOwnerCapability(CAPABILITY)
    const repository = new OwnerTestRepository(hash)

    const response = await ownerStatusResponse(
      new Request(`https://onceveil.test/api/secrets/${ID}/owner`, {
        headers: { Authorization: `Bearer ${'b'.repeat(64)}` },
      }),
      ID,
      repository,
      1_100,
    )

    expect(response.status).toBe(404)
    await expect(response.json()).resolves.toEqual({ error: 'not_found' })
  })

  it('revokes without returning ciphertext or capability material', async () => {
    const hash = await hashOwnerCapability(CAPABILITY)
    const repository = new OwnerTestRepository(hash)

    const response = await ownerRevokeResponse(
      new Request(`https://onceveil.test/api/secrets/${ID}/owner`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${CAPABILITY}` },
      }),
      ID,
      repository,
      1_100,
    )

    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body).toEqual({ state: 'REVOKED', expiresAtMs: 2_000 })
    expect(JSON.stringify(body)).not.toContain(CAPABILITY)
    expect('ciphertext' in (body as Record<string, unknown>)).toBe(false)
  })
})
