import { existsSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { getBrandingConfig } from '../src/runtime/node-request-context'

const originalEnvironment = {
  ONCEVEIL_BRAND_NAME: process.env.ONCEVEIL_BRAND_NAME,
  ONCEVEIL_SQLITE_PATH: process.env.ONCEVEIL_SQLITE_PATH,
}

afterEach(() => {
  for (const [name, value] of Object.entries(originalEnvironment)) {
    if (value === undefined) {
      delete process.env[name]
    } else {
      process.env[name] = value
    }
  }
})

describe('Node branding runtime', () => {
  it('resolves branding without opening or migrating SQLite', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'onceveil-branding-'))
    const databasePath = path.join(directory, 'nested', 'onceveil.sqlite')

    try {
      process.env.ONCEVEIL_BRAND_NAME = 'Runtime Brand'
      process.env.ONCEVEIL_SQLITE_PATH = databasePath

      expect(getBrandingConfig().name).toBe('Runtime Brand')
      expect(existsSync(path.dirname(databasePath))).toBe(false)
      expect(existsSync(databasePath)).toBe(false)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})
