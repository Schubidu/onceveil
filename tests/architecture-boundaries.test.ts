import { readdir, readFile } from 'node:fs/promises'
import { builtinModules } from 'node:module'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const coreDirectory = path.resolve('src/core')
const nodeBuiltins = new Set(builtinModules.map((module) => module.replace(/^node:/, '')))

function isForbiddenImport(specifier: string) {
  const normalized = specifier.replace(/^node:/, '')

  return (
    specifier === 'react' ||
    specifier.startsWith('react/') ||
    specifier === 'react-dom' ||
    specifier.startsWith('react-dom/') ||
    specifier.startsWith('@tanstack/') ||
    specifier.startsWith('@cloudflare/') ||
    specifier.startsWith('cloudflare:') ||
    nodeBuiltins.has(normalized)
  )
}

function importedSpecifiers(source: string, fileName: string) {
  const sourceFile = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true)
  const specifiers: string[] = []

  function visit(node: ts.Node) {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text)
    }

    if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isStringLiteral(node.arguments[0]) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === 'require'))
    ) {
      specifiers.push(node.arguments[0].text)
    }

    ts.forEachChild(node, visit)
  }

  visit(sourceFile)
  return specifiers
}

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
  it.each([
    'react',
    'react/jsx-runtime',
    'react-dom',
    'react-dom/client',
    '@tanstack/react-router',
    '@cloudflare/workers-types',
    'cloudflare:workers',
    'node:fs',
    'fs',
  ])('rejects runtime or framework import %s', (specifier) => {
    expect(isForbiddenImport(specifier)).toBe(true)
  })

  it('does not depend on framework or runtime modules', async () => {
    const files = await sourceFiles(coreDirectory)

    expect(files.length).toBeGreaterThan(0)

    for (const file of files) {
      const source = await readFile(file, 'utf8')
      const forbidden = importedSpecifiers(source, file).filter(isForbiddenImport)
      expect(forbidden, file).toEqual([])
    }
  })
})
