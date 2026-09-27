import { describe, expect, it } from 'vitest'

import {
  generateSecretId,
  prepareSecretRecord,
  type PreparedSecretRecord,
  type SecretRepository,
} from '../../src/core/secret'

const OWNER_KEY_HASH = 'a'.repeat(64)
const REPLAY_ORIGINAL = '1'.repeat(64)
const REPLAY_REPLACEMENT = '2'.repeat(64)
const REPLAY_SECRET = '3'.repeat(64)
const REPLAY_SAME_PAYLOAD = '4'.repeat(64)

export interface SecretRepositoryFixture {
  repository: SecretRepository
  close?(): void | Promise<void>
}

export type SecretRepositoryFixtureFactory = () =>
  | SecretRepositoryFixture
  | Promise<SecretRepositoryFixture>

function record(ciphertext = new Uint8Array([7, 8, 9])): PreparedSecretRecord {
  const prepared = prepareSecretRecord(generateSecretId(), ciphertext, 100, 900)

  if (!prepared.ok) {
    throw new Error(`failed to prepare test secret: ${prepared.reason}`)
  }

  return prepared.record
}

async function withRepository<Result>(
  factory: SecretRepositoryFixtureFactory,
  operation: (repository: SecretRepository) => Promise<Result>,
): Promise<Result> {
  const fixture = await factory()

  try {
    return await operation(fixture.repository)
  } finally {
    await fixture.close?.()
  }
}

export function secretRepositoryContract(
  name: string,
  factory: SecretRepositoryFixtureFactory,
): void {
  describe(`SecretRepository contract: ${name}`, () => {
    it('inserts each identifier only once and never overwrites an existing record', async () => {
      await withRepository(factory, async (repository) => {
        const original = record()
        const replacement = {
          ...original,
          ciphertext: new Uint8Array([9, 9, 9]),
        } as PreparedSecretRecord

        expect(await repository.create(original, REPLAY_ORIGINAL, OWNER_KEY_HASH)).toEqual({
          kind: 'created',
          id: original.id,
        })
        expect(await repository.create(replacement, REPLAY_REPLACEMENT, OWNER_KEY_HASH)).toEqual({
          kind: 'duplicate_id',
        })

        const consumed = await repository.consume(original.id, 500)
        expect(consumed.kind).toBe('revealed')

        if (consumed.kind === 'revealed') {
          expect(consumed.ciphertext).toEqual(original.ciphertext)
        }
      })
    })

    it('allows only one concurrent create for the same identifier', async () => {
      await withRepository(factory, async (repository) => {
        const secret = record()

        const results = await Promise.all([
          repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH),
          repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH),
          repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH),
        ])

        expect(results.filter((result) => result.kind === 'created')).toHaveLength(1)
        expect(results.filter((result) => result.kind === 'replayed')).toHaveLength(2)
        for (const result of results) {
          expect(result.kind === 'created' || result.kind === 'replayed').toBe(true)
          if (result.kind === 'created' || result.kind === 'replayed') {
            expect(result.id).toBe(secret.id)
          }
        }
      })
    })

    it('reuses the original public identifier when the same create request is replayed', async () => {
      await withRepository(factory, async (repository) => {
        const original = record()
        const replay = record()

        expect(await repository.create(original, REPLAY_SAME_PAYLOAD, OWNER_KEY_HASH)).toEqual({
          kind: 'created',
          id: original.id,
        })
        expect(await repository.create(replay, REPLAY_SAME_PAYLOAD, OWNER_KEY_HASH)).toEqual({
          kind: 'replayed',
          id: original.id,
        })
      })
    })

    it('rejects replaying the same payload key with a different TTL', async () => {
      await withRepository(factory, async (repository) => {
        const original = record()
        const changedTtl = prepareSecretRecord(
          generateSecretId(),
          original.ciphertext,
          original.createdAtMs,
          800,
        )

        if (!changedTtl.ok) {
          throw new Error(`failed to prepare replay conflict: ${changedTtl.reason}`)
        }

        expect(await repository.create(original, REPLAY_SAME_PAYLOAD, OWNER_KEY_HASH)).toEqual({
          kind: 'created',
          id: original.id,
        })
        expect(
          await repository.create(changedTtl.record, REPLAY_SAME_PAYLOAD, OWNER_KEY_HASH),
        ).toEqual({
          kind: 'replay_conflict',
        })
      })
    })

    it('allows only one concurrent consume winner', async () => {
      await withRepository(factory, async (repository) => {
        const secret = record()
        await repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH)

        const results = await Promise.all([
          repository.consume(secret.id, 500),
          repository.consume(secret.id, 500),
          repository.consume(secret.id, 500),
        ])

        const winners = results.filter((result) => result.kind === 'revealed')
        const losers = results.filter((result) => result.kind === 'unavailable')

        expect(winners).toHaveLength(1)
        expect(losers).toHaveLength(2)
        expect(losers.every((result) => !('ciphertext' in result))).toBe(true)
        expect((await repository.getStatus(secret.id, OWNER_KEY_HASH, 500))?.state).toBe('CONSUMED')
      })
    })

    it('allows consume or revoke to win, but never both', async () => {
      await withRepository(factory, async (repository) => {
        const secret = record()
        await repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH)

        const [consume, revoke] = await Promise.all([
          repository.consume(secret.id, 500),
          repository.revoke(secret.id, OWNER_KEY_HASH, 500),
        ])

        const consumeWon = consume.kind === 'revealed'
        const revokeWon = revoke.kind === 'revoked'

        expect(Number(consumeWon) + Number(revokeWon)).toBe(1)
        expect((await repository.getStatus(secret.id, OWNER_KEY_HASH, 500))?.state).toBe(
          consumeWon ? 'CONSUMED' : 'REVOKED',
        )

        if (consumeWon) {
          expect(revoke).toEqual({ kind: 'unavailable', state: 'CONSUMED' })
        } else {
          expect(consume).toEqual({ kind: 'unavailable', state: 'REVOKED' })
        }
      })
    })

    it('treats a wrong owner capability as not found', async () => {
      await withRepository(factory, async (repository) => {
        const secret = record()
        await repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH)

        await expect(repository.getStatus(secret.id, 'b'.repeat(64), 500)).resolves.toBeUndefined()
        await expect(repository.revoke(secret.id, 'b'.repeat(64), 500)).resolves.toEqual({
          kind: 'not_found',
        })
        expect((await repository.getStatus(secret.id, OWNER_KEY_HASH, 500))?.state).toBe(
          'AVAILABLE',
        )
      })
    })

    it('never exposes ciphertext through status or revoke operations', async () => {
      await withRepository(factory, async (repository) => {
        const secret = record()
        await repository.create(secret, REPLAY_SECRET, OWNER_KEY_HASH)

        const status = await repository.getStatus(secret.id, OWNER_KEY_HASH, 500)
        expect(status?.state).toBe('AVAILABLE')
        expect(status && 'ciphertext' in status).toBe(false)

        const revoked = await repository.revoke(secret.id, OWNER_KEY_HASH, 500)
        expect(revoked.kind).toBe('revoked')
        expect('ciphertext' in revoked).toBe(false)
      })
    })
  })
}
