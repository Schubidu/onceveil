import { DatabaseSync } from 'node:sqlite'

import type {
  D1BindingValue,
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
  D1SessionLike,
} from './d1-secret-repository'

type NodeSqliteBindingValue = string | number | null | Uint8Array
type StatementKind = 'rows' | 'mutation'

function bindingValue(value: D1BindingValue): NodeSqliteBindingValue {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value.slice(0))
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice()
  }

  return value
}

function statementKind(query: string): StatementKind {
  const operation = /^\s*([A-Z]+)/i.exec(query)?.[1]?.toUpperCase()

  if (operation === 'SELECT' || operation === 'PRAGMA') {
    return 'rows'
  }

  if (operation === 'INSERT' || operation === 'UPDATE' || operation === 'DELETE') {
    return 'mutation'
  }

  throw new TypeError(`Unsupported Node SQLite prepared statement: ${operation ?? 'unknown'}`)
}

class NodeSqlitePreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly database: DatabaseSync,
    private readonly query: string,
    private readonly values: NodeSqliteBindingValue[] = [],
  ) {}

  bind(...values: D1BindingValue[]): D1PreparedStatementLike {
    return new NodeSqlitePreparedStatement(this.database, this.query, values.map(bindingValue))
  }

  async run<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>> {
    return this.execute<Row>()
  }

  async first<Row = Record<string, unknown>>(): Promise<Row | null> {
    if (statementKind(this.query) !== 'rows') {
      throw new TypeError('Node SQLite first() requires a row-producing statement')
    }

    const row = this.database.prepare(this.query).get(...this.values) as Row | undefined
    return row ?? null
  }

  ownedBy(database: DatabaseSync): boolean {
    return this.database === database
  }

  execute<Row = Record<string, unknown>>(): D1ResultLike<Row> {
    const statement = this.database.prepare(this.query)

    if (statementKind(this.query) === 'rows') {
      return {
        success: true,
        results: statement.all(...this.values) as Row[],
        meta: { changes: 0 },
      }
    }

    const result = statement.run(...this.values)
    return {
      success: true,
      results: [],
      meta: { changes: Number(result.changes) },
    }
  }
}

export class NodeSqliteDatabase implements D1DatabaseLike {
  private readonly database: DatabaseSync

  constructor(path: string) {
    this.database = new DatabaseSync(path, { timeout: 5_000 })
    this.database.exec('PRAGMA foreign_keys = ON')
  }

  prepare(query: string): D1PreparedStatementLike {
    return new NodeSqlitePreparedStatement(this.database, query)
  }

  withSession(_constraint?: 'first-primary' | 'first-unconstrained' | string): D1SessionLike {
    return this
  }

  async batch(statements: D1PreparedStatementLike[]): Promise<D1ResultLike[]> {
    const ownedStatements = statements.map((statement) => {
      if (
        !(statement instanceof NodeSqlitePreparedStatement) ||
        !statement.ownedBy(this.database)
      ) {
        throw new TypeError('Node SQLite batch received a foreign prepared statement')
      }

      return statement
    })

    this.database.exec('BEGIN IMMEDIATE')

    try {
      const results = ownedStatements.map((statement) => statement.execute())
      this.database.exec('COMMIT')
      return results
    } catch (error) {
      this.database.exec('ROLLBACK')
      throw error
    }
  }

  exec(sql: string): void {
    this.database.exec(sql)
  }

  close(): void {
    this.database.close()
  }
}
