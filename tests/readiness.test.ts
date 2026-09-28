import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../src/adapters/d1-secret-repository'
import {
  checkSecretDatabaseReadiness,
  requiredRuntimeEnvironmentForRequest,
  runtimeEnvironmentForHostname,
} from '../src/runtime/readiness'

interface DatabaseState {
  environmentTable?: boolean
  secretsTable?: boolean
  revealProofsTable?: boolean
  mcpHandoffsTable?: boolean
  marker?: string
  schemaError?: boolean
  databaseError?: boolean
}

function fakeDatabase(state: DatabaseState): D1DatabaseLike {
  return {
    prepare(query: string): D1PreparedStatementLike {
      return {
        bind() {
          return this
        },
        async run<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>> {
          return { success: true, results: [] }
        },
        async first<Row = Record<string, unknown>>(): Promise<Row | null> {
          if (state.databaseError) {
            throw new Error('database unavailable')
          }

          if (query.includes("name = 'onceveil_environment'")) {
            return (state.environmentTable ? { present: 1 } : null) as Row | null
          }

          if (query.includes("name = 'secrets'")) {
            return (state.secretsTable ? { present: 1 } : null) as Row | null
          }

          if (query.includes("name = 'reveal_proofs'")) {
            return (state.revealProofsTable ? { present: 1 } : null) as Row | null
          }

          if (query.includes("name = 'mcp_handoffs'")) {
            return (state.mcpHandoffsTable !== false ? { present: 1 } : null) as Row | null
          }

          if (query.includes('SELECT environment FROM onceveil_environment')) {
            return (state.marker ? { environment: state.marker } : null) as Row | null
          }

          if (
            query.includes('FROM secrets LIMIT 0') ||
            query.includes('FROM reveal_proofs LIMIT 0') ||
            query.includes('FROM mcp_handoffs LIMIT 0')
          ) {
            if (state.schemaError) {
              throw new Error('schema mismatch')
            }
            return null
          }

          throw new Error(`unexpected query: ${query}`)
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
}

describe('runtime readiness', () => {
  it.each([
    ['ots-preview.schult.dev', 'preview'],
    ['pr-17.ots-preview.schult.dev', 'preview'],
    ['feat-issue-4-d1-one-time-flow-onceveil.schult.workers.dev', 'preview'],
    ['localhost', 'preview'],
    ['ots.schult.dev', 'production'],
    ['onceveil.schult.workers.dev', 'production'],
    ['unknown.example', undefined],
  ] as const)('classifies %s as %s', (hostname, expected) => {
    expect(runtimeEnvironmentForHostname(hostname)).toBe(expected)
  })

  it('fails closed when a runtime requiring an environment receives an unknown host', () => {
    expect(requiredRuntimeEnvironmentForRequest(new Request('https://unknown.example/ready'))).toBe(
      'unavailable',
    )
    expect(
      requiredRuntimeEnvironmentForRequest(new Request('https://ots-preview.schult.dev/ready')),
    ).toBe('preview')
  })

  it('reports ready only when the bound database has the expected schema and marker', async () => {
    await expect(
      checkSecretDatabaseReadiness(
        fakeDatabase({
          environmentTable: true,
          secretsTable: true,
          revealProofsTable: true,
          marker: 'preview',
        }),
        'preview',
      ),
    ).resolves.toEqual({
      status: 'ready',
      database: 'ok',
      environment: 'preview',
    })
  })

  it('supports self-hosted readiness without a deployment environment marker', async () => {
    await expect(
      checkSecretDatabaseReadiness(
        fakeDatabase({
          secretsTable: true,
          revealProofsTable: true,
        }),
      ),
    ).resolves.toEqual({
      status: 'ready',
      database: 'ok',
    })
  })

  it('reports migration_required when the MCP handoff migration is missing', async () => {
    await expect(
      checkSecretDatabaseReadiness(
        fakeDatabase({
          environmentTable: true,
          secretsTable: true,
          revealProofsTable: true,
          mcpHandoffsTable: false,
          marker: 'preview',
        }),
        'preview',
      ),
    ).resolves.toEqual({
      status: 'not_ready',
      database: 'migration_required',
    })
  })

  it('reports migration_required when required tables are missing', async () => {
    await expect(
      checkSecretDatabaseReadiness(
        fakeDatabase({ secretsTable: true, revealProofsTable: true }),
        'preview',
      ),
    ).resolves.toEqual({
      status: 'not_ready',
      database: 'migration_required',
    })
  })

  it('reports an environment mismatch without relabeling the database', async () => {
    await expect(
      checkSecretDatabaseReadiness(
        fakeDatabase({
          environmentTable: true,
          secretsTable: true,
          revealProofsTable: true,
          marker: 'production',
        }),
        'preview',
      ),
    ).resolves.toEqual({
      status: 'not_ready',
      database: 'environment_mismatch',
      expected: 'preview',
      actual: 'production',
    })
  })

  it('reports migration_required when a required schema column is missing', async () => {
    await expect(
      checkSecretDatabaseReadiness(
        fakeDatabase({
          environmentTable: true,
          secretsTable: true,
          revealProofsTable: true,
          marker: 'preview',
          schemaError: true,
        }),
        'preview',
      ),
    ).resolves.toEqual({
      status: 'not_ready',
      database: 'migration_required',
    })
  })

  it('keeps deployment schema verification aligned with runtime readiness', async () => {
    const source = await readFile(path.resolve('scripts/d1-environment.mjs'), 'utf8')

    expect(source).toContain('owner_key_hash')
    expect(source).toContain('mcp_handoffs')
  })

  it('reports unavailable when the database cannot be queried', async () => {
    await expect(
      checkSecretDatabaseReadiness(fakeDatabase({ databaseError: true }), 'preview'),
    ).resolves.toEqual({
      status: 'not_ready',
      database: 'unavailable',
    })
  })
})
