import { readFile } from 'node:fs/promises'

const expected = {
  binding: 'DB',
  databaseId: 'a8f3fce5-8226-40f1-804a-96677743f541',
  turnstileSiteKey: '0x4AAAAAAFEfxfEZ8ZH4YiZn',
}

const raw = await readFile('dist/server/wrangler.json', 'utf8')
const config = JSON.parse(raw)
const bindings = config?.previews?.d1_databases

if (!Array.isArray(bindings)) {
  throw new Error('Generated Wrangler config is missing previews.d1_databases')
}

const database = bindings.find((binding) => binding?.binding === expected.binding)
if (!database) {
  throw new Error(`Generated Wrangler config is missing Preview D1 binding ${expected.binding}`)
}

if (database.database_id !== expected.databaseId) {
  throw new Error(
    `Generated Preview D1 binding points at ${database.database_id ?? 'no database_id'} instead of ${expected.databaseId}`,
  )
}

if (config?.previews?.vars?.TURNSTILE_SITE_KEY !== expected.turnstileSiteKey) {
  throw new Error('Generated Wrangler config is missing the Preview TURNSTILE_SITE_KEY')
}

console.log(`Generated Preview D1 binding ${expected.binding} -> ${expected.databaseId}`)
console.log('Generated Preview TURNSTILE_SITE_KEY is configured')
