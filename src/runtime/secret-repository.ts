import { env } from 'cloudflare:workers'

import { D1SecretRepository, type D1DatabaseLike } from '../adapters/d1-secret-repository'
import type { SecretRepository } from '../core/secret'

export class SecretDatabaseUnavailableError extends Error {
  constructor() {
    super('Secret database binding is unavailable')
    this.name = 'SecretDatabaseUnavailableError'
  }
}

export function getSecretRepository(): SecretRepository {
  const database = (env as { DB?: D1DatabaseLike }).DB
  if (!database) {
    throw new SecretDatabaseUnavailableError()
  }

  return new D1SecretRepository(database)
}
