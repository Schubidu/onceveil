import { DatabaseSync } from 'node:sqlite'

import type {
  D1BindingValue,
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../src/adapters/d1-secret-repository'

function sqliteValue(value: D1BindingValue) {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  }

  return value
}

class SQLiteD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly database: DatabaseSync,
    private readonly query: string,
    private readonly values: D1BindingValue[] = [],
  ) {}

  bind(...values: D1BindingValue[]): D1PreparedStatementLike {
    return new SQLiteD1PreparedStatement(this.database, this.query, values)
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

export class SQLiteD1TestDatabase implements D1DatabaseLike {
  readonly database = new DatabaseSync(':memory:')
  private queue = Promise.resolve()

  prepare(query: string): D1PreparedStatementLike {
    return new SQLiteD1PreparedStatement(this.database, query)
  }

  withSession(): SQLiteD1TestDatabase {
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
        if (!(statement instanceof SQLiteD1PreparedStatement)) {
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

  close(): void {
    this.database.close()
  }
}
