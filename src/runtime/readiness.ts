import type { D1DatabaseLike } from '../adapters/d1-secret-repository'

export type RuntimeEnvironment = 'production' | 'preview'

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
      database: 'environment_unknown'
    }
  | {
      status: 'not_ready'
      database: 'unavailable'
    }

export function runtimeEnvironmentForHostname(hostname: string): RuntimeEnvironment | undefined {
  const normalized = hostname.toLowerCase()

  const isPreview =
    normalized === 'ots-preview.schult.dev' ||
    normalized.endsWith('.ots-preview.schult.dev') ||
    normalized.endsWith('-onceveil.schult.workers.dev') ||
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized === '127.0.0.1' ||
    normalized === '[::1]'

  if (isPreview) {
    return 'preview'
  }

  if (normalized === 'ots.schult.dev' || normalized === 'onceveil.schult.workers.dev') {
    return 'production'
  }

  return undefined
}

export function runtimeEnvironmentForRequest(request: Request): RuntimeEnvironment | undefined {
  return runtimeEnvironmentForHostname(new URL(request.url).hostname)
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
        'SELECT id, ciphertext, created_at_ms, expires_at_ms, state, consumed_at_ms, revoked_at_ms, consume_token, replay_key FROM secrets LIMIT 0',
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
