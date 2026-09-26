import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { D1RevealProofRepository } from '../src/adapters/d1-reveal-proof-repository'
import {
  D1SecretRepository,
  type D1BindingValue,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
  type D1ResultLike,
} from '../src/adapters/d1-secret-repository'
import { decryptSecret, encryptSecret } from '../src/browser/secret-crypto'
import { REVEAL_PROOF_TTL_MS } from '../src/core/reveal-protection'
import type { SecretId } from '../src/core/secret'
import {
  prepareRevealProofResponse,
  protectedRevealResponse,
  verifyRevealProofResponse,
} from '../src/runtime/reveal-protection-http'
import {
  createSecretResponse,
  MAX_CREATE_REQUEST_BYTES,
  revealSecretResponse,
} from '../src/runtime/secret-http'

function sqliteValue(value: D1BindingValue) {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  }

  return value
}

const PUBLIC_ID = 'f'.repeat(32) as SecretId
const allocatePublicId = () => PUBLIC_ID

class SQLitePreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly database: DatabaseSync,
    private readonly query: string,
    private readonly values: D1BindingValue[] = [],
  ) {}

  bind(...values: D1BindingValue[]): D1PreparedStatementLike {
    return new SQLitePreparedStatement(this.database, this.query, values)
  }

  async run<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>> {
    return this.execute<Row>()
  }

  async first<Row = Record<string, unknown>>(): Promise<Row | null> {
    const statement = this.database.prepare(this.query)
    return (statement.get(...this.values.map(sqliteValue)) as Row | undefined) ?? null
  }

  execute<Row = Record<string, unknown>>(): D1ResultLike<Row> {
    const statement = this.database.prepare(this.query)
    const values = this.values.map(sqliteValue)

    if (/^\s*SELECT\b/i.test(this.query)) {
      return {
        success: true,
        results: statement.all(...values) as Row[],
        meta: { changes: 0 },
      }
    }

    const result = statement.run(...values)
    return {
      success: true,
      results: [],
      meta: { changes: Number(result.changes) },
    }
  }
}

class SQLiteD1Database implements D1DatabaseLike {
  readonly database = new DatabaseSync(':memory:')
  private queue = Promise.resolve()

  prepare(query: string): D1PreparedStatementLike {
    return new SQLitePreparedStatement(this.database, query)
  }

  withSession(): SQLiteD1Database {
    return this
  }

  async batch(statements: D1PreparedStatementLike[]): Promise<D1ResultLike[]> {
    const previous = this.queue
    let release: (() => void) | undefined
    this.queue = new Promise<void>((resolve) => {
      release = resolve
    })

    await previous
    await Promise.resolve()

    this.database.exec('BEGIN IMMEDIATE')
    try {
      const results = statements.map((statement) => {
        if (!(statement instanceof SQLitePreparedStatement)) {
          throw new Error('unexpected statement implementation')
        }

        return statement.execute()
      })
      this.database.exec('COMMIT')
      return results
    } catch (error) {
      this.database.exec('ROLLBACK')
      throw error
    } finally {
      release?.()
    }
  }

  close() {
    this.database.close()
  }
}

describe('D1 one-time HTTP flow', () => {
  let d1: SQLiteD1Database
  let repository: D1SecretRepository
  let proofRepository: D1RevealProofRepository
  let verificationSequence: number

  beforeEach(async () => {
    d1 = new SQLiteD1Database()
    const migration = await readFile(path.resolve('migrations/0001_secrets.sql'), 'utf8')
    const replayMigration = await readFile(
      path.resolve('migrations/0003_secret_replay_key.sql'),
      'utf8',
    )
    d1.database.exec(migration)
    const proofMigration = await readFile(path.resolve('migrations/0004_reveal_proofs.sql'), 'utf8')
    const proofHandoffMigration = await readFile(
      path.resolve('migrations/0005_reveal_proof_verification.sql'),
      'utf8',
    )
    const legacyShareMigration = await readFile(
      path.resolve('migrations/0006_expire_legacy_share_links.sql'),
      'utf8',
    )
    d1.database.exec(replayMigration)
    d1.database.exec(proofMigration)
    d1.database.exec(proofHandoffMigration)
    d1.database.exec(legacyShareMigration)
    repository = new D1SecretRepository(d1)
    proofRepository = new D1RevealProofRepository(d1)
    verificationSequence = 0
  })

  afterEach(() => {
    d1.close()
  })

  function revealAuthorization(id: SecretId): string {
    const row = d1.database.prepare('SELECT replay_key FROM secrets WHERE id = ?').get(id) as
      | { replay_key?: string }
      | undefined
    if (typeof row?.replay_key !== 'string') {
      throw new Error('missing reveal authorization')
    }

    return row.replay_key
  }

  function nextVerificationId(): string {
    verificationSequence += 1
    return verificationSequence.toString(16).padStart(32, '0')
  }

  async function prepareProof(id: SecretId, nowMs: number) {
    const proof = await proofRepository.prepare(
      id,
      revealAuthorization(id),
      nextVerificationId(),
      nowMs,
    )
    if (!proof) {
      throw new Error('proof preparation failed')
    }

    return proof
  }

  async function storeTestSecret(plaintext: string, nowMs = 0) {
    const encrypted = await encryptSecret(plaintext)
    const response = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      nowMs,
      allocatePublicId,
    )
    expect(response.status).toBe(201)
  }

  it('reports the failing D1 create stage without secret material', async () => {
    const failingDatabase: D1DatabaseLike = {
      prepare() {
        return {
          bind() {
            return this
          },
          async run() {
            throw new Error('D1_ERROR: test failure')
          },
          async first() {
            return null
          },
        }
      },
      withSession() {
        return this
      },
      async batch() {
        return []
      },
    }

    const failingRepository = new D1SecretRepository(failingDatabase)
    const encrypted = await encryptSecret('must stay secret')
    const create = createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      failingRepository,
      1_000,
      allocatePublicId,
    )

    await expect(create).rejects.toMatchObject({
      name: 'D1CreateError',
      stage: 'run',
      detail: 'D1_ERROR: test failure',
    })
  })

  it('stores only encrypted payload data and decrypts only in the winning browser', async () => {
    const plaintext = 'this must never enter D1'
    const encrypted = await encryptSecret(plaintext)
    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    expect(create.status).toBe(201)
    await expect(create.clone().json()).resolves.toEqual({ id: PUBLIC_ID })
    expect(create.headers.get('cache-control')).toBe('no-store')
    expect(create.headers.get('referrer-policy')).toBe('no-referrer')

    const row = d1.database
      .prepare('SELECT ciphertext FROM secrets WHERE id = ?')
      .get(PUBLIC_ID) as { ciphertext: Uint8Array }
    const stored = new TextDecoder().decode(row.ciphertext)

    expect(stored).not.toContain(plaintext)
    expect(stored).not.toContain(encrypted.fragment)
    expect(stored).not.toContain('"key"')

    const responses = await Promise.all(
      Array.from({ length: 8 }, () => revealSecretResponse(PUBLIC_ID, repository, 1_001)),
    )

    const winners = responses.filter((response) => response.status === 200)
    const losers = responses.filter((response) => response.status === 410)

    expect(winners).toHaveLength(1)
    expect(losers).toHaveLength(7)

    const payload: unknown = await winners[0].json()
    await expect(decryptSecret(payload, encrypted.fragment)).resolves.toBe(plaintext)
  })

  it('allocates the public reveal identifier on the server', async () => {
    const encrypted = await encryptSecret('server id')
    expect(encrypted.payload.contextId).not.toBe(PUBLIC_ID)

    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    expect(create.status).toBe(201)
    await expect(create.json()).resolves.toEqual({ id: PUBLIC_ID })

    const stored = d1.database.prepare('SELECT id FROM secrets LIMIT 1').get() as { id: string }
    expect(stored.id).toBe(PUBLIC_ID)
    expect(stored.id).not.toBe(encrypted.payload.contextId)
  })

  it('returns the original public identifier when the same encrypted create is replayed', async () => {
    const encrypted = await encryptSecret('retry safe')
    const body = JSON.stringify({ payload: encrypted.payload })
    const secondId = 'e'.repeat(32) as SecretId
    const ids = [PUBLIC_ID, secondId]
    let nextId = 0
    const allocate = () => ids[nextId++] ?? secondId

    const first = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      }),
      repository,
      1_000,
      allocate,
    )
    const replay = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      }),
      repository,
      1_001,
      allocate,
    )

    expect(first.status).toBe(201)
    await expect(first.json()).resolves.toEqual({ id: PUBLIC_ID })
    expect(replay.status).toBe(200)
    await expect(replay.json()).resolves.toEqual({ id: PUBLIC_ID })

    const rows = d1.database.prepare('SELECT id FROM secrets').all() as Array<{ id: string }>
    expect(rows).toEqual([{ id: PUBLIC_ID }])
  })

  it('rejects a replay that changes the TTL without creating another row', async () => {
    const encrypted = await encryptSecret('retry ttl conflict')
    const firstBody = JSON.stringify({ payload: encrypted.payload, ttlMs: 100 })
    const replayBody = JSON.stringify({ payload: encrypted.payload, ttlMs: 200 })
    const secondId = 'e'.repeat(32) as SecretId
    const ids = [PUBLIC_ID, secondId]
    let nextId = 0
    const allocate = () => ids[nextId++] ?? secondId

    const first = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: firstBody,
      }),
      repository,
      1_000,
      allocate,
    )
    const conflict = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: replayBody,
      }),
      repository,
      1_001,
      allocate,
    )

    expect(first.status).toBe(201)
    expect(conflict.status).toBe(409)
    await expect(conflict.json()).resolves.toEqual({ error: 'replay_conflict' })

    const rows = d1.database
      .prepare('SELECT id, created_at_ms, expires_at_ms FROM secrets')
      .all() as Array<{ id: string; created_at_ms: number; expires_at_ms: number }>
    expect(rows).toEqual([{ id: PUBLIC_ID, created_at_ms: 1_000, expires_at_ms: 1_100 }])
  })

  it('rejects null TTL instead of treating it as the default', async () => {
    const encrypted = await encryptSecret('invalid ttl')
    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload, ttlMs: null }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    expect(create.status).toBe(400)
    await expect(create.json()).resolves.toEqual({ error: 'invalid_ttl' })
    const count = d1.database.prepare('SELECT COUNT(*) AS count FROM secrets').get() as {
      count: number
    }
    expect(count.count).toBe(0)
  })

  it('rejects oversized streamed request bodies before JSON/base64 decoding', async () => {
    const chunk = new Uint8Array(MAX_CREATE_REQUEST_BYTES)
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk)
        controller.enqueue(new Uint8Array([1]))
        controller.close()
      },
    })

    const request = new Request('https://onceveil.test/api/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' })

    const create = await createSecretResponse(request, repository, 1_000, allocatePublicId)

    expect(create.status).toBe(413)
    await expect(create.json()).resolves.toEqual({ error: 'payload_too_large' })
    const count = d1.database.prepare('SELECT COUNT(*) AS count FROM secrets').get() as {
      count: number
    }
    expect(count.count).toBe(0)
  })

  it('rejects an oversized declared content length before reading the body', async () => {
    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(MAX_CREATE_REQUEST_BYTES + 1),
        },
        body: '{}',
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    expect(create.status).toBe(413)
    await expect(create.json()).resolves.toEqual({ error: 'payload_too_large' })
  })

  it('strips untrusted extra payload fields before persistence', async () => {
    const encrypted = await encryptSecret('allowlisted payload')
    const maliciousPayload = {
      ...encrypted.payload,
      key: encrypted.fragment,
      fragment: encrypted.fragment,
    }

    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: maliciousPayload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    expect(create.status).toBe(201)

    const row = d1.database
      .prepare('SELECT ciphertext FROM secrets WHERE id = ?')
      .get(PUBLIC_ID) as { ciphertext: Uint8Array }
    const stored = new TextDecoder().decode(row.ciphertext)

    expect(stored).not.toContain(encrypted.fragment)
    expect(stored).not.toContain('"key"')
    expect(stored).not.toContain('"fragment"')
  })

  it.each([
    { nonce: 'x', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAA' },
    { nonce: 'AAAAAAAAAAAAAAAA', ciphertext: 'y' },
  ])('rejects malformed encrypted payload sizes before persistence', async (override) => {
    const encrypted = await encryptSecret('validation')
    const payload = {
      ...encrypted.payload,
      ...override,
    }

    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    expect(create.status).toBe(400)
    const count = d1.database.prepare('SELECT COUNT(*) AS count FROM secrets').get() as {
      count: number
    }
    expect(count.count).toBe(0)
  })

  it('normalizes ArrayBuffer ciphertext returned by the D1 adapter', async () => {
    const encrypted = await encryptSecret('array buffer blob')
    const encoded = new TextEncoder().encode(JSON.stringify(encrypted.payload))

    const database: D1DatabaseLike = {
      prepare() {
        throw new Error('not used')
      },
      withSession() {
        const session = {
          prepare(_query: string) {
            return {
              bind() {
                return this
              },
              async run<Row = Record<string, unknown>>() {
                return { success: true, results: [] as Row[] }
              },
              async first<Row = Record<string, unknown>>() {
                return {
                  id: PUBLIC_ID,
                  created_at_ms: 1_000,
                  expires_at_ms: 2_000,
                  state: 'CONSUMED',
                } as Row
              },
            }
          },
          async batch() {
            return [
              { success: true, results: [] },
              { success: true, results: [] },
              {
                success: true,
                results: [
                  {
                    id: PUBLIC_ID,
                    ciphertext: encoded.buffer.slice(0),
                    created_at_ms: 1_000,
                    expires_at_ms: 2_000,
                    state: 'CONSUMED',
                  },
                ],
              },
              { success: true, results: [] },
            ]
          },
        }

        return session
      },
      async batch() {
        return []
      },
    }

    const arrayBufferRepository = new D1SecretRepository(database)
    const result = await arrayBufferRepository.consume(PUBLIC_ID, 1_001)

    expect(result.kind).toBe('revealed')
    if (result.kind === 'revealed') {
      const payload: unknown = JSON.parse(new TextDecoder().decode(result.ciphertext))
      await expect(decryptSecret(payload, encrypted.fragment)).resolves.toBe('array buffer blob')
    }
  })

  it('requires the fragment-only authorization before preparing a reveal proof', async () => {
    const encrypted = await encryptSecret('authorized proof preparation')
    await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    const rejected = await prepareRevealProofResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          authorization: '0'.repeat(64),
          verificationId: nextVerificationId(),
        }),
      }),
      PUBLIC_ID,
      proofRepository,
      1_001,
    )
    expect(rejected.status).toBe(403)

    const count = d1.database.prepare('SELECT COUNT(*) AS count FROM reveal_proofs').get() as {
      count: number
    }
    expect(count.count).toBe(0)

    const verificationId = nextVerificationId()
    const prepared = await prepareRevealProofResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          authorization: revealAuthorization(PUBLIC_ID),
          verificationId,
        }),
      }),
      PUBLIC_ID,
      proofRepository,
      1_001,
    )
    expect(prepared.status).toBe(201)
    await expect(prepared.json()).resolves.toMatchObject({
      verificationId,
      proof: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    })
  })

  it('bounds active pending proofs per secret', async () => {
    await storeTestSecret('bounded pending proofs')
    const authorization = revealAuthorization(PUBLIC_ID)

    const prepared = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        proofRepository.prepare(
          PUBLIC_ID,
          authorization,
          (index + 1).toString(16).padStart(32, '0'),
          1_000,
        ),
      ),
    )

    expect(prepared.filter((proof) => proof !== undefined)).toHaveLength(3)
    const rows = d1.database
      .prepare(
        `SELECT COUNT(*) AS count
         FROM reveal_proofs
         WHERE secret_id = ?
           AND verified_at_ms IS NULL
           AND consumed_at_ms IS NULL
           AND expires_at_ms > ?`,
      )
      .get(PUBLIC_ID, 1_000) as { count: number }
    expect(rows.count).toBe(3)
  })

  it('explicitly expires pre-v2 secrets during the security migration', async () => {
    const database = new DatabaseSync(':memory:')
    try {
      database.exec(await readFile(path.resolve('migrations/0001_secrets.sql'), 'utf8'))
      database
        .prepare(
          `INSERT INTO secrets
            (id, ciphertext, created_at_ms, expires_at_ms, state)
           VALUES (?, ?, ?, ?, 'AVAILABLE')`,
        )
        .run(PUBLIC_ID, new Uint8Array([1]), 1_000, 2_000)

      database.exec(await readFile(path.resolve('migrations/0003_secret_replay_key.sql'), 'utf8'))
      database.exec(
        await readFile(path.resolve('migrations/0006_expire_legacy_share_links.sql'), 'utf8'),
      )

      const row = database.prepare('SELECT state, replay_key FROM secrets WHERE id = ?').get(
        PUBLIC_ID,
      ) as { state: string; replay_key: string | null }
      expect(row).toEqual({ state: 'EXPIRED', replay_key: null })
    } finally {
      database.close()
    }
  })

  it('requires a valid one-time proof before the protected reveal can consume', async () => {
    const encrypted = await encryptSecret('protected reveal')
    await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    const invalid = await protectedRevealResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: 'not-a-proof' }),
      }),
      PUBLIC_ID,
      proofRepository,
      repository,
      1_001,
    )
    expect(invalid.status).toBe(403)
    await expect(repository.getStatus(PUBLIC_ID, 1_001)).resolves.toMatchObject({
      state: 'AVAILABLE',
    })

    const issued = await prepareProof(PUBLIC_ID, 1_002)
    await expect(proofRepository.verify(PUBLIC_ID, issued.verificationId, 1_003)).resolves.toBe(
      true,
    )
    const revealed = await protectedRevealResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: issued.value }),
      }),
      PUBLIC_ID,
      proofRepository,
      repository,
      1_004,
    )
    expect(revealed.status).toBe(200)

    const replay = await protectedRevealResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: issued.value }),
      }),
      PUBLIC_ID,
      proofRepository,
      repository,
      1_005,
    )
    expect(replay.status).toBe(403)
  })

  it('prunes consumed and expired reveal proofs when issuing a new proof', async () => {
    await storeTestSecret('proof cleanup')
    const expired = await prepareProof(PUBLIC_ID, 1_000)
    const consumed = await prepareProof(PUBLIC_ID, 2_000)
    await expect(proofRepository.verify(PUBLIC_ID, consumed.verificationId, 2_001)).resolves.toBe(
      true,
    )
    await expect(proofRepository.consume(PUBLIC_ID, consumed.value, 2_002)).resolves.toBe(true)

    const cleanupAt = expired.expiresAtMs
    await prepareProof(PUBLIC_ID, cleanupAt)

    const count = d1.database.prepare('SELECT COUNT(*) AS count FROM reveal_proofs').get() as {
      count: number
    }
    expect(count.count).toBe(1)
  })

  it('keeps the proof unusable until its matching verification is completed', async () => {
    await storeTestSecret('pending proof')
    const proof = await prepareProof(PUBLIC_ID, 1_000)
    const otherId = 'e'.repeat(32) as SecretId

    await expect(proofRepository.consume(PUBLIC_ID, proof.value, 1_001)).resolves.toBe(false)
    await expect(proofRepository.verify(otherId, proof.verificationId, 1_001)).resolves.toBe(false)
    await expect(proofRepository.verify(PUBLIC_ID, '0'.repeat(32), 1_001)).resolves.toBe(false)
    await expect(proofRepository.verify(PUBLIC_ID, proof.verificationId, 1_001)).resolves.toBe(true)
    await expect(proofRepository.consume(PUBLIC_ID, proof.value, 1_002)).resolves.toBe(true)
  })

  it('allows only one concurrent consume of the same verified reveal proof', async () => {
    await storeTestSecret('concurrent proof')
    const proof = await prepareProof(PUBLIC_ID, 1_000)
    await expect(proofRepository.verify(PUBLIC_ID, proof.verificationId, 1_001)).resolves.toBe(true)

    const results = await Promise.all(
      Array.from({ length: 8 }, () => proofRepository.consume(PUBLIC_ID, proof.value, 1_002)),
    )

    expect(results.filter(Boolean)).toHaveLength(1)
    expect(results.filter((result) => !result)).toHaveLength(7)
  })

  it('does not consume the secret when a proof is expired, replayed, or bound elsewhere', async () => {
    const encrypted = await encryptSecret('proof failures leave available')
    await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    const expired = await prepareProof(PUBLIC_ID, 1_001)
    await expect(proofRepository.verify(PUBLIC_ID, expired.verificationId, 1_002)).resolves.toBe(
      true,
    )
    const expiredResponse = await protectedRevealResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: expired.value }),
      }),
      PUBLIC_ID,
      proofRepository,
      repository,
      1_002 + REVEAL_PROOF_TTL_MS,
    )
    expect(expiredResponse.status).toBe(403)

    const spent = await prepareProof(PUBLIC_ID, 2_000)
    await expect(proofRepository.verify(PUBLIC_ID, spent.verificationId, 2_001)).resolves.toBe(true)
    await expect(proofRepository.consume(PUBLIC_ID, spent.value, 2_002)).resolves.toBe(true)
    const replayedResponse = await protectedRevealResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: spent.value }),
      }),
      PUBLIC_ID,
      proofRepository,
      repository,
      2_003,
    )
    expect(replayedResponse.status).toBe(403)

    const otherId = 'e'.repeat(32) as SecretId
    const otherProof = await prepareProof(PUBLIC_ID, 3_000)
    await expect(proofRepository.verify(PUBLIC_ID, otherProof.verificationId, 3_001)).resolves.toBe(
      true,
    )
    const boundResponse = await protectedRevealResponse(
      new Request(`https://onceveil.test/api/secrets/${otherId}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: otherProof.value }),
      }),
      otherId,
      proofRepository,
      repository,
      3_002,
    )
    expect(boundResponse.status).toBe(403)

    await expect(repository.getStatus(PUBLIC_ID, 3_002)).resolves.toMatchObject({
      state: 'AVAILABLE',
    })
  })

  it('leaves the secret available when Turnstile verification is unavailable', async () => {
    const encrypted = await encryptSecret('provider outage')
    await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    const prepared = await prepareProof(PUBLIC_ID, 1_001)
    const verification = await verifyRevealProofResponse(
      new Request(`https://onceveil.test/api/secrets/${PUBLIC_ID}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'token', verificationId: prepared.verificationId }),
      }),
      PUBLIC_ID,
      {
        async verify() {
          return { kind: 'unavailable' }
        },
      },
      proofRepository,
      1_002,
    )

    expect(verification.status).toBe(503)
    await expect(proofRepository.consume(PUBLIC_ID, prepared.value, 1_003)).resolves.toBe(false)
    await expect(repository.getStatus(PUBLIC_ID, 1_003)).resolves.toMatchObject({
      state: 'AVAILABLE',
    })
  })

  it('expires before reveal and never returns ciphertext', async () => {
    const encrypted = await encryptSecret('short lived')
    const create = await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload, ttlMs: 10 }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )
    expect(create.status).toBe(201)

    const reveal = await revealSecretResponse(PUBLIC_ID, repository, 1_010)
    expect(reveal.status).toBe(410)
    await expect(reveal.json()).resolves.toEqual({ error: 'unavailable' })
  })

  it('does not consume a valid secret when a different reveal ID is rejected', async () => {
    const encrypted = await encryptSecret('still available')
    await createSecretResponse(
      new Request('https://onceveil.test/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted.payload }),
      }),
      repository,
      1_000,
      allocatePublicId,
    )

    const invalid = await revealSecretResponse('not-an-id', repository, 1_001)
    expect(invalid.status).toBe(404)

    const valid = await revealSecretResponse(PUBLIC_ID, repository, 1_001)
    expect(valid.status).toBe(200)
  })
})
