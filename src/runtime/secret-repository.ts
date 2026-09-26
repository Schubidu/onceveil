import { env } from 'cloudflare:workers'

import { D1SecretRepository, type D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { SecretRepository } from '../core/secret'

type RuntimeEnvironment = 'production' | 'preview'

interface OnceveilEnv {
  APP_ENV?: RuntimeEnvironment
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

export function getSecretRepository(): SecretRepository {
  const database = runtimeEnv().DB
  if (!database) {
    throw new SecretDatabaseUnavailableError()
  }

  return new D1SecretRepository(database)
}

export async function assertSecretDatabaseEnvironment(): Promise<void> {
  const { APP_ENV: expected, DB: database } = runtimeEnv()
  if (!database || !expected) {
    throw new SecretDatabaseUnavailableError()
  }

  let row: EnvironmentRow | null
  try {
    row = await database
      .prepare('SELECT environment FROM onceveil_environment WHERE id = 1 LIMIT 1')
      .first<EnvironmentRow>()
  } catch {
    throw new SecretDatabaseEnvironmentError(expected, 'unmarked')
  }

  const actual = row?.environment ?? 'unmarked'
  if (actual !== expected) {
    throw new SecretDatabaseEnvironmentError(expected, actual)
  }
}
