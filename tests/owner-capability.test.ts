import { describe, expect, it } from 'vitest'

import { ownerPath, takeOwnerCapability } from '../src/browser/owner-capability'
import {
  generateOwnerCapability,
  hashOwnerCapability,
  isValidOwnerCapability,
  isValidOwnerCapabilityHash,
  type OwnerCapability,
} from '../src/core/owner-capability'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId

describe('owner capability', () => {
  it('generates an independent 256-bit capability and hashes it for storage', async () => {
    const capability = generateOwnerCapability()
    const hash = await hashOwnerCapability(capability)

    expect(capability).toMatch(/^[0-9a-f]{64}$/)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
    expect(hash).not.toBe(capability)
    expect(isValidOwnerCapability(capability)).toBe(true)
    expect(isValidOwnerCapabilityHash(hash)).toBe(true)
  })

  it('keeps the owner capability in the fragment and removes it from browser history', () => {
    const capability = 'a'.repeat(64) as OwnerCapability
    const path = ownerPath(SECRET_ID, capability)
    expect(path).toBe(`/o/${SECRET_ID}#v1.${capability}`)

    const replacements: Array<{ state: unknown; url: string | URL | null | undefined }> = []
    const location = {
      hash: `#v1.${capability}`,
      pathname: `/o/${SECRET_ID}`,
      search: '',
    }
    const history = {
      state: { route: 'owner' },
      replaceState(state: unknown, _unused: string, url?: string | URL | null) {
        replacements.push({ state, url })
      },
    }

    expect(takeOwnerCapability(location, history)).toBe(capability)
    expect(replacements).toEqual([{ state: history.state, url: `/o/${SECRET_ID}` }])
  })

  it('rejects malformed owner fragments after scrubbing them from the URL', () => {
    const replacements: Array<string | URL | null | undefined> = []
    const location = {
      hash: '#v1.not-a-capability',
      pathname: `/o/${SECRET_ID}`,
      search: '?source=test',
    }
    const history = {
      state: null,
      replaceState(_state: unknown, _unused: string, url?: string | URL | null) {
        replacements.push(url)
      },
    }

    expect(takeOwnerCapability(location, history)).toBeUndefined()
    expect(replacements).toEqual([`/o/${SECRET_ID}?source=test`])
  })
})
