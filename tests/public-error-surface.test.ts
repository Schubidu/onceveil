import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

describe('public error surfaces', () => {
  it.each([
    'src/routes/api.secrets.ts',
    'src/routes/api.secrets.$id.owner.ts',
    'src/routes/api.secrets.$id.reveal.ts',
  ])(
    '%s does not serialize database diagnostics',
    async (routePath) => {
      const source = await readFile(path.resolve(routePath), 'utf8')

      expect(source).not.toContain("error: 'database_environment_mismatch'")
      expect(source).not.toContain("error: 'd1_create_failed'")
      expect(source).not.toContain('body?.stage')
      expect(source).not.toContain('body?.detail')
      expect(source).not.toContain('body?.expected')
      expect(source).not.toContain('body?.actual')
    },
  )

  it('keeps readiness diagnostics internal', async () => {
    const source = await readFile(path.resolve('src/routes/ready.ts'), 'utf8')

    expect(source).toContain("status: ready ? 'ready' : 'not_ready'")
    expect(source).not.toContain('database:')
    expect(source).not.toContain('expected:')
    expect(source).not.toContain('actual:')
  })
})
