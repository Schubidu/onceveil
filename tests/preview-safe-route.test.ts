import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import { Route as OwnerRoute } from '../src/routes/o.$id'
import { Route as ShareRoute } from '../src/routes/s.$id'
import { isSecretSurface } from '../src/runtime/security-headers'

describe('preview-safe share landing route', () => {
  it('locks the plaintext field while a create request is in flight', async () => {
    const source = await readFile(path.resolve('src/routes/index.tsx'), 'utf8')

    expect(source).toContain('disabled={creating}')
  })

  it('executes the passive HEAD handler without revealing or consuming anything', async () => {
    const configuredHandlers = ShareRoute.options.server?.handlers
    expect(configuredHandlers).toBeDefined()
    expect(typeof configuredHandlers).not.toBe('function')
    if (!configuredHandlers || typeof configuredHandlers === 'function') {
      throw new Error('expected static route handlers')
    }

    const handlers = configuredHandlers as Record<string, unknown>
    expect(handlers).not.toHaveProperty('GET')

    const head = handlers.HEAD
    expect(head).toBeTypeOf('function')
    if (typeof head !== 'function') {
      throw new Error('expected HEAD handler')
    }

    const response = await head({
      request: new Request('https://ots-preview.schult.dev/s/0123456789abcdef0123456789abcdef', {
        method: 'HEAD',
      }),
      params: { id: '0123456789abcdef0123456789abcdef' },
      context: undefined,
    } as never)

    expect(response).toBeInstanceOf(Response)
    expect(response.status).toBe(200)
    expect(await response.text()).toBe('')
  })

  it('clears plaintext and hides the create form after successful creation', async () => {
    const source = await readFile(path.resolve('src/routes/index.tsx'), 'utf8')

    expect(source).toContain("setSecret('')")
    expect(source).toContain('!shareUrl && !ownerUrl')
    expect(source).toContain('Create another secret')
  })

  it('uses native sharing only for the recipient link when available', async () => {
    const source = await readFile(path.resolve('src/routes/index.tsx'), 'utf8')

    expect(source).toContain("typeof navigator.share === 'function'")
    expect(source).toContain('navigator.share({ url: value })')
    expect(source).toContain('Share one-time link')
  })

  it('keeps owner pages passive and covered by secret-surface headers', async () => {
    const configuredHandlers = OwnerRoute.options.server?.handlers
    expect(configuredHandlers).toBeDefined()
    expect(typeof configuredHandlers).not.toBe('function')
    if (!configuredHandlers || typeof configuredHandlers === 'function') {
      throw new Error('expected static owner route handlers')
    }

    const handlers = configuredHandlers as Record<string, unknown>
    expect(handlers).not.toHaveProperty('GET')
    expect(handlers.HEAD).toBeTypeOf('function')

    expect(
      isSecretSurface(new Request('https://onceveil.test/o/0123456789abcdef0123456789abcdef')),
    ).toBe(true)
  })

  it('reveals only from the explicit browser action', async () => {
    const source = await readFile(path.resolve('src/routes/s.$id.tsx'), 'utf8')

    expect(source).not.toContain('loader:')
    expect(source).not.toContain('getSecretRepository')
    expect(source).not.toContain('consume(')
    expect(source).toContain("method: 'POST'")
    expect(source).toContain("'X-Onceveil-Reveal': '1'")
    expect(source).toContain('/reveal')
  })

  it('copies revealed plaintext only from an explicit user action without hiding it from assistive technology', async () => {
    const source = await readFile(path.resolve('src/routes/s.$id.tsx'), 'utf8')

    expect(source).toContain('navigator.clipboard.writeText(plaintext)')
    expect(source).toContain('<pre className="secret-value">{plaintext}</pre>')
    expect(source).toContain('aria-label="Copy revealed secret to clipboard"')
  })

  it('reloads owner capability on hash navigation and ignores stale owner operations', async () => {
    const source = await readFile(path.resolve('src/routes/o.$id.tsx'), 'utf8')

    expect(source).toContain("window.addEventListener('hashchange', loadOwner)")
    expect(source).toContain('generation.current === currentGeneration')
  })

  it('clears decryption capability and plaintext across page lifecycle restores', async () => {
    const source = await readFile(path.resolve('src/routes/s.$id.tsx'), 'utf8')

    expect(source).toContain("window.addEventListener('pagehide', clearSensitiveState)")
    expect(source).toContain("window.addEventListener('pageshow', clearRestoredState)")
    expect(source).toContain('fragment.current = undefined')
    expect(source).toContain('setPlaintext(undefined)')
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
