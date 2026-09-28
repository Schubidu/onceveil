import { spawn } from 'node:child_process'
import { cp, mkdtemp, rm, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

const directory = await mkdtemp(path.join(os.tmpdir(), 'onceveil-node-smoke-'))
const runtimeDirectory = path.join(directory, 'runtime')
const databasePath = path.join(directory, 'onceveil.sqlite')
const port = 31_000 + (process.pid % 1_000)
const origin = `http://127.0.0.1:${port}`
let logs = ''

const runtimeEnvironment = { ...process.env }
delete runtimeEnvironment.CI
delete runtimeEnvironment.TEST

await cp('.output', runtimeDirectory, { recursive: true })

const server = spawn(process.execPath, [path.join(runtimeDirectory, 'server/index.mjs')], {
  cwd: runtimeDirectory,
  env: {
    ...runtimeEnvironment,
    HOST: '127.0.0.1',
    PORT: String(port),
    ONCEVEIL_SQLITE_PATH: databasePath,
    ONCEVEIL_REVEAL_PROTECTION: 'none',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
})

server.stdout.setEncoding('utf8')
server.stderr.setEncoding('utf8')
server.stdout.on('data', (chunk) => {
  logs += chunk
})
server.stderr.on('data', (chunk) => {
  logs += chunk
})

function fetchLocal(pathname) {
  return fetch(`${origin}${pathname}`, {
    headers: {
      Connection: 'close',
    },
  })
}

function hasExited() {
  return server.exitCode !== null || server.signalCode !== null
}

function assertCleanExit() {
  if (server.exitCode !== 0 || server.signalCode !== null) {
    throw new Error(
      `Node production runtime exited unexpectedly (code ${server.exitCode}, signal ${server.signalCode})\n${logs}`,
    )
  }
}

async function waitUntilReady() {
  const deadline = Date.now() + 15_000
  let lastError

  while (Date.now() < deadline) {
    if (hasExited()) {
      throw new Error(
        `Node server exited before readiness (code ${server.exitCode}, signal ${server.signalCode})\n${logs}`,
      )
    }

    try {
      const response = await fetchLocal('/ready')
      const body = await response.json()
      if (response.status === 200 && body?.status === 'ready') {
        return
      }

      lastError = new Error(`readiness returned ${response.status}: ${JSON.stringify(body)}`)
    } catch (error) {
      lastError = error
    }

    await delay(100)
  }

  throw new Error(
    `Node server did not become ready: ${lastError instanceof Error ? lastError.message : 'unknown error'}\n${logs}`,
  )
}

async function stopServer() {
  if (hasExited()) {
    assertCleanExit()
    return
  }

  const exited = new Promise((resolve) => server.once('exit', resolve))
  let timeout
  const timedOut = new Promise((resolve) => {
    timeout = setTimeout(() => resolve('timeout'), 7_000)
  })

  server.kill('SIGTERM')

  const result = await Promise.race([exited.then(() => 'exited'), timedOut])
  clearTimeout(timeout)

  if (result === 'timeout' && !hasExited()) {
    server.kill('SIGKILL')
    await exited
    throw new Error('Node production runtime did not stop within 7 seconds after SIGTERM')
  }

  assertCleanExit()
}

try {
  await waitUntilReady()
  await stat(databasePath)

  const response = await fetchLocal('/')
  if (!response.ok) {
    throw new Error(`Node server root returned ${response.status}`)
  }

  const body = await response.text()
  if (!body.includes('id="product-title"')) {
    throw new Error('Node server root did not render the application')
  }

  const csp = response.headers.get('content-security-policy') ?? ''
  if (csp.includes('challenges.cloudflare.com')) {
    throw new Error('Self-hosted none mode unexpectedly enables Turnstile CSP')
  }

  console.log('Standalone Node production runtime smoke check passed')
} finally {
  await stopServer()
  await rm(directory, { recursive: true, force: true })
}
