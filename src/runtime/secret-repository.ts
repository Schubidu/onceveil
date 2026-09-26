import { env } from 'cloudflare:workers'

import { D1SecretRepository, type D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { SecretRepository } from '../core/secret'

export type RuntimeEnvironment = 'production' | 'preview'

interface OnceveilEnv {
  DB?: D1DatabaseLike
}

interface EnvironmentRow {
  environment: string
}

interface PresentRow {
  present: number
}

export type SecretDatabaseReadiness =
  | {
      status: 'ready'
      database: 'ok'
      environment: RuntimeEnvironment
    }
  | {
      status: 'not_ready'
      database: 'migration_required'
    }
  | {
      status: 'not_ready'
      database: 'environment_mismatch'
      expected: RuntimeEnvironment
      actual: string
    }
  | {
      status: 'not_ready'
      database: 'unavailable'
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

export function runtimeEnvironmentForHostname(hostname: string): RuntimeEnvironment {
  const isPreview =
    hostname === 'ots-preview.schult.dev' ||
    hostname.endsWith('.ots-preview.schult.dev') ||
    hostname.endsWith('-onceveil.schult.workers.dev')

  return isPreview ? 'preview' : 'production'
}

export function runtimeEnvironmentForRequest(request: Request): RuntimeEnvironment {
  return runtimeEnvironmentForHostname(new URL(request.url).hostname)
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

export async function checkSecretDatabaseReadiness(
  database: D1DatabaseLike,
  expected: RuntimeEnvironment,
): Promise<SecretDatabaseReadiness> {
  try {
    const environmentTable = await database
      .prepare(
        "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'onceveil_environment'",
      )
      .first<PresentRow>()
    const secretsTable = await database
      .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'secrets'")
      .first<PresentRow>()

    if (!environmentTable || !secretsTable) {
      return { status: 'not_ready', database: 'migration_required' }
    }

    const marker = await database
      .prepare('SELECT environment FROM onceveil_environment WHERE id = 1 LIMIT 1')
      .first<EnvironmentRow>()
    const actual = marker?.environment ?? 'missing-marker'
    if (actual !== expected) {
      return {
        status: 'not_ready',
        database: 'environment_mismatch',
        expected,
        actual,
      }
    }

    await database
      .prepare(
        'SELECT id, ciphertext, created_at_ms, expires_at_ms, state, consumed_at_ms, revoked_at_ms, consume_token FROM secrets LIMIT 0',
      )
      .first()

    return {
      status: 'ready',
      database: 'ok',
      environment: expected,
    }
  } catch {
    return { status: 'not_ready', database: 'unavailable' }
  }
}
