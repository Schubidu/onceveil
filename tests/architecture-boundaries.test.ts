import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

const coreDirectory = path.resolve('src/core')
const forbiddenImports =
  /from\s+['"](?:react(?:\/[^'"]*)?|@tanstack\/[^'"]+|node:[^'"]+|cloudflare:[^'"]+)['"]/

async function sourceFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = await Promise.all(
    entries.map(async (entry) => {
      const absolutePath = path.join(directory, entry.name)

      if (entry.isDirectory()) {
        return sourceFiles(absolutePath)
      }

      return entry.name.endsWith('.ts') || entry.name.endsWith('.tsx') ? [absolutePath] : []
    }),
  )

  return files.flat()
}

describe('core architecture boundary', () => {
  it('does not depend on framework or runtime modules', async () => {
    const files = await sourceFiles(coreDirectory)

    expect(files.length).toBeGreaterThan(0)

    for (const file of files) {
      const source = await readFile(file, 'utf8')
      expect(source, file).not.toMatch(forbiddenImports)
    }
  })
})
