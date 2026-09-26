import { env } from 'cloudflare:workers'

import { D1SecretRepository, type D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { SecretRepository } from '../core/secret'
import type { RuntimeEnvironment } from './readiness'

interface OnceveilEnv {
  DB?: D1DatabaseLike
}

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

function runtimeEnv(): OnceveilEnv {
  return env as OnceveilEnv
}

export function getSecretDatabase(): D1DatabaseLike {
  const database = runtimeEnv().DB
  if (!database) {
    throw new SecretDatabaseUnavailableError()
  }

  return database
}

export function getSecretRepository(): SecretRepository {
  return new D1SecretRepository(getSecretDatabase())
}

export async function assertSecretDatabaseEnvironment(expected: RuntimeEnvironment): Promise<void> {
  const database = getSecretDatabase()

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
