import { mkdirSync } from 'node:fs'
import path from 'node:path'

import { altchaRevealProtectionConfiguration } from '../adapters/altcha-reveal-protection'
import { NodeSqliteDatabase } from '../adapters/node-sqlite-database'
import { applySqliteMigrations } from '../adapters/sqlite-migrations'
import type { OnceveilRequestContext, RevealProtectionRuntime } from './request-context'

const DEFAULT_SQLITE_PATH = './data/onceveil.sqlite'

let opened:
  | {
      path: string
      database: NodeSqliteDatabase
    }
  | undefined

function sqlitePath(): string {
  const configured = process.env.ONCEVEIL_SQLITE_PATH?.trim()
  return configured || DEFAULT_SQLITE_PATH
}

function databaseForPath(configuredPath: string): NodeSqliteDatabase {
  if (opened?.path === configuredPath) {
    return opened.database
  }

  opened?.database.close()
  opened = undefined

  if (configuredPath !== ':memory:') {
    mkdirSync(path.dirname(path.resolve(configuredPath)), { recursive: true })
  }

  const database = new NodeSqliteDatabase(configuredPath)

  try {
    applySqliteMigrations(database)
  } catch (error) {
    database.close()
    throw error
  }

  opened = {
    path: configuredPath,
    database,
  }
  return database
}

export function nodeRevealProtection(
  value: string | undefined,
  altchaSecret?: string,
): RevealProtectionRuntime {
  if (value === 'none') {
    return { provider: 'none' }
  }

  if (value === 'altcha') {
    const configuration = altchaRevealProtectionConfiguration(altchaSecret)
    return configuration ? { provider: 'altcha', ...configuration } : { provider: 'unavailable' }
  }

  return { provider: 'unavailable' }
}

export function createRequestContext(_request: Request): OnceveilRequestContext {
  let secretDatabase: NodeSqliteDatabase | undefined

  try {
    secretDatabase = databaseForPath(sqlitePath())
  } catch {
    secretDatabase = undefined
  }

  return {
    secretDatabase,
    databaseEnvironment: 'markerless',
    revealProtection: nodeRevealProtection(
      process.env.ONCEVEIL_REVEAL_PROTECTION,
      process.env.ONCEVEIL_ALTCHA_SECRET,
    ),
  }
}
