import { spawn } from 'node:child_process'

const wranglerCommand = process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler'
const validEnvironments = new Set(['production', 'preview'])
const validActions = new Set(['mark', 'verify'])

function runWrangler(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(wranglerCommand, args, {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })

    child.once('error', reject)
    child.once('close', (code) => {
      if (code !== 0) {
        reject(
          new Error(
            `wrangler d1 execute failed with exit code ${code ?? 'unknown'}${stderr ? `: ${stderr.trim()}` : ''}`,
          ),
        )
        return
      }

      resolve(stdout.trim())
    })
  })
}

function parseOutput(stdout) {
  const parsed = JSON.parse(stdout)
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('wrangler d1 execute returned no query results')
  }

  if (parsed.some((entry) => entry?.success !== true)) {
    throw new Error('wrangler d1 execute reported an unsuccessful query')
  }

  return parsed
}

function markerFrom(entries) {
  for (const entry of entries) {
    if (!Array.isArray(entry.results)) {
      continue
    }

    for (const row of entry.results) {
      if (typeof row?.environment === 'string') {
        return row.environment
      }
    }
  }

  return undefined
}

async function main() {
  const [action, expected, databaseName, configPath] = process.argv.slice(2)
  if (!validActions.has(action) || !validEnvironments.has(expected) || !databaseName) {
    throw new Error(
      'Usage: node scripts/d1-environment.mjs <mark|verify> <production|preview> <database-name> [config-path]',
    )
  }

  const markerStatement =
    action === 'mark'
      ? `INSERT INTO onceveil_environment (id, environment) VALUES (1, '${expected}') ON CONFLICT(id) DO NOTHING; SELECT environment FROM onceveil_environment WHERE id = 1 LIMIT 1;`
      : `SELECT environment FROM onceveil_environment WHERE id = 1 LIMIT 1; SELECT id, ciphertext, created_at_ms, expires_at_ms, state, consumed_at_ms, revoked_at_ms, consume_token FROM secrets LIMIT 0;`

  const args = [
    'd1',
    'execute',
    databaseName,
    '--remote',
    '--json',
    '--command',
    markerStatement,
  ]
  if (configPath) {
    args.push('--config', configPath)
  }

  const entries = parseOutput(await runWrangler(args))
  const actual = markerFrom(entries)
  if (actual !== expected) {
    throw new Error(
      `D1 environment marker mismatch: expected ${expected}, got ${actual ?? 'missing-marker'}`,
    )
  }

  console.log(`D1 environment ${action} passed: ${databaseName} -> ${expected}`)
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error)
  process.exitCode = 1
})
