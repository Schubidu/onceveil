import { readFile } from 'node:fs/promises'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import {
  DEFAULT_BRANDING,
  parseBrandingConfig,
  resolveBrandingConfig,
} from '../src/core/branding'

describe('deployment branding', () => {
  it('uses the Onceveil presentation by default', () => {
    expect(resolveBrandingConfig()).toEqual(DEFAULT_BRANDING)
    expect(DEFAULT_BRANDING).toEqual({
      name: 'Onceveil',
      theme: {
        accent: '#f0f6fc',
      },
    })
  })

  it('accepts a constrained alternate deployment brand', () => {
    expect(
      resolveBrandingConfig({
        name: 'Acme Vault',
        logo: '/brand/logo.svg?revision=1',
        favicon: '/brand/favicon.svg',
        accent: '#12ABef',
      }),
    ).toEqual({
      name: 'Acme Vault',
      logo: '/brand/logo.svg?revision=1',
      favicon: '/brand/favicon.svg',
      theme: {
        accent: '#12ABef',
      },
    })
  })

  it('falls back safely for markup, external assets and arbitrary style values', () => {
    expect(
      parseBrandingConfig({
        name: '<strong>Injected</strong>',
        logo: 'https://tracker.example/logo.svg',
        favicon: '//tracker.example/favicon.svg',
        theme: {
          accent: 'url(https://tracker.example/style.css)',
        },
      }),
    ).toEqual(DEFAULT_BRANDING)
  })

  it.each([
    'https://example.com/logo.svg',
    '//example.com/logo.svg',
    'data:image/svg+xml;base64,PHN2Zz4=',
    'javascript:alert(1)',
    'logo.svg',
  ])('rejects non-root-relative asset location %s', (logo) => {
    expect(parseBrandingConfig({ logo }).logo).toBeUndefined()
  })

  it('keeps brandable UI surfaces free of literal product-name markup', async () => {
    for (const file of [
      'src/routes/__root.tsx',
      'src/routes/index.tsx',
      'src/routes/o.$id.tsx',
      'src/routes/s.$id.tsx',
    ]) {
      const source = await readFile(path.resolve(file), 'utf8')
      expect(source, file).not.toContain("'Onceveil'")
      expect(source, file).not.toContain('>Onceveil<')
    }
  })
})
