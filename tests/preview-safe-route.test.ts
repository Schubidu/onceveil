import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

describe('preview-safe share landing route', () => {
  it('has no passive GET loader or repository access and only reveals on explicit POST', async () => {
    const source = await readFile(path.resolve('src/routes/s.$id.tsx'), 'utf8')

    expect(source).toContain('HEAD:')
    expect(source).not.toContain('GET:')
    expect(source).not.toContain('loader:')
    expect(source).not.toContain('getSecretRepository')
    expect(source).not.toContain('consume(')
    expect(source).toContain("method: 'POST'")
    expect(source).toContain("'X-Onceveil-Reveal': '1'")
    expect(source).toContain('/reveal')
  })

  it('does not auto-trigger reveal during page initialization', async () => {
    const source = await readFile(path.resolve('src/routes/s.$id.tsx'), 'utf8')

    const effect = source.slice(
      source.indexOf('useEffect'),
      source.indexOf('async function reveal'),
    )
    expect(effect).toContain('takeShareFragment')
    expect(effect).not.toContain('fetch(')
  })
})
