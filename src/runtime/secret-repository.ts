import { D1SecretRepository, type D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { SecretRepository } from '../core/secret'
import type { OnceveilRequestContext } from './request-context'

interface EnvironmentRow {
  environment: string
}

export class SecretDatabaseUnavailableError extends Error {
  constructor() {
    super('Secret database binding is unavailable')
    this.name = 'SecretDatabaseUnavailableError'
  }
}

export class SecretDatabaseEnvironmentError extends Error {
  constructor(
    readonly expected: string,
    readonly actual: string,
  ) {
    super(`Secret database environment mismatch: expected ${expected}, got ${actual}`)
    this.name = 'SecretDatabaseEnvironmentError'
  }
}

export function getSecretDatabase(context: OnceveilRequestContext): D1DatabaseLike {
  if (context.databaseEnvironment === 'unavailable' || !context.secretDatabase) {
    throw new SecretDatabaseUnavailableError()
  }

  return context.secretDatabase
}

export function getSecretRepository(context: OnceveilRequestContext): SecretRepository {
  return new D1SecretRepository(getSecretDatabase(context))
}

export async function assertSecretDatabaseEnvironment(
  context: OnceveilRequestContext,
): Promise<void> {
  const database = getSecretDatabase(context)
  const expected = context.databaseEnvironment

  if (expected === 'markerless') {
    return
  }

  let row: EnvironmentRow | null
  try {
    row = await database
      .prepare('SELECT environment FROM onceveil_environment WHERE id = 1 LIMIT 1')
      .first<EnvironmentRow>()
  } catch (error) {
    const detail =
      error instanceof Error && error.message
        ? error.message.replace(/\s+/g, ' ').slice(0, 180)
        : 'unknown query error'
    throw new SecretDatabaseEnvironmentError(expected, `query-error:${detail}`)
  }

  const actual = row?.environment ?? 'missing-marker'
  if (actual !== expected) {
    throw new SecretDatabaseEnvironmentError(expected, actual)
  }
}
