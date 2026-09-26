import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  D1SecretRepository,
  type D1BindingValue,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
  type D1ResultLike,
} from '../src/adapters/d1-secret-repository'
import { decryptSecret, encryptSecret } from '../src/browser/secret-crypto'
import { createSecretResponse, revealSecretResponse } from '../src/runtime/secret-http'

function sqliteValue(value: D1BindingValue) {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  }

  return value
}

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

  beforeEach(async () => {
    d1 = new SQLiteD1Database()
    const migration = await readFile(path.resolve('migrations/0001_secrets.sql'), 'utf8')
    d1.database.exec(migration)
    repository = new D1SecretRepository(d1)
  })

  afterEach(() => {
    d1.close()
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
    )

    expect(create.status).toBe(201)
    expect(create.headers.get('cache-control')).toBe('no-store')
    expect(create.headers.get('referrer-policy')).toBe('no-referrer')

    const row = d1.database
      .prepare('SELECT ciphertext FROM secrets WHERE id = ?')
      .get(encrypted.payload.id) as { ciphertext: Uint8Array }
    const stored = new TextDecoder().decode(row.ciphertext)

    expect(stored).not.toContain(plaintext)
    expect(stored).not.toContain(encrypted.fragment)
    expect(stored).not.toContain('"key"')

    const responses = await Promise.all(
      Array.from({ length: 8 }, () =>
        revealSecretResponse(encrypted.payload.id, repository, 1_001),
      ),
    )

    const winners = responses.filter((response) => response.status === 200)
    const losers = responses.filter((response) => response.status === 410)

    expect(winners).toHaveLength(1)
    expect(losers).toHaveLength(7)

    const payload: unknown = await winners[0].json()
    await expect(decryptSecret(payload, encrypted.fragment)).resolves.toBe(plaintext)
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
    )
    expect(create.status).toBe(201)

    const reveal = await revealSecretResponse(encrypted.payload.id, repository, 1_010)
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
    )

    const invalid = await revealSecretResponse('not-an-id', repository, 1_001)
    expect(invalid.status).toBe(404)

    const valid = await revealSecretResponse(encrypted.payload.id, repository, 1_001)
    expect(valid.status).toBe(200)
  })
})
