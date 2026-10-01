import { execFile } from 'node:child_process'
import { createHash, randomBytes, webcrypto } from 'node:crypto'
import { promisify } from 'node:util'

import { solveChallenge } from 'altcha-lib'
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2'

const execFileAsync = promisify(execFile)
const projectName = `onceveil-ci-${process.pid}`
const port = 32_000 + (process.pid % 1_000)
const origin = `http://127.0.0.1:${port}`
const altchaSecret = randomBytes(32).toString('hex')

const composeEnv = {
  ...process.env,
  COMPOSE_PROJECT_NAME: projectName,
  ONCEVEIL_BIND_ADDRESS: '127.0.0.1',
  ONCEVEIL_PORT: String(port),
  ONCEVEIL_BRAND_NAME: 'CI Vault',
  ONCEVEIL_BRAND_LOGO: '/branding/ci-logo.svg',
  ONCEVEIL_BRAND_FAVICON: '/branding/ci-favicon.svg',
  ONCEVEIL_BRAND_ACCENT: '#6E56CF',
  ONCEVEIL_REVEAL_PROTECTION: 'altcha',
  ONCEVEIL_ALTCHA_SECRET: altchaSecret,
}

async function command(file, args, env = composeEnv) {
  return execFileAsync(file, args, {
    cwd: process.cwd(),
    env,
    maxBuffer: 10 * 1024 * 1024,
  })
}

async function compose(args, env = composeEnv) {
  return command('docker', ['compose', ...args], env)
}

async function assertComposeDefaultsToAltcha() {
  const env = { ...composeEnv }
  delete env.ONCEVEIL_REVEAL_PROTECTION
  delete env.ONCEVEIL_ALTCHA_SECRET

  const { stdout } = await compose(['config'], env)
  if (!stdout.includes('ONCEVEIL_REVEAL_PROTECTION: altcha')) {
    throw new Error('docker compose must default to ALTCHA reveal protection')
  }
}

async function assertTrustedNetworkNoneIsExplicitlyAvailable() {
  const env = {
    ...composeEnv,
    ONCEVEIL_REVEAL_PROTECTION: 'none',
    ONCEVEIL_ALTCHA_SECRET: '',
  }
  const { stdout } = await compose(['config'], env)
  if (!stdout.includes('ONCEVEIL_REVEAL_PROTECTION: none')) {
    throw new Error('docker compose must preserve explicit trusted-network none mode')
  }
}

async function containerId() {
  const { stdout } = await compose(['ps', '-q', 'onceveil'])
  return stdout.trim()
}

async function waitUntilHealthy() {
  const deadline = Date.now() + 90_000
  let lastStatus = 'container unavailable'

  while (Date.now() < deadline) {
    const id = await containerId()
    if (id) {
      try {
        const { stdout } = await command('docker', [
          'inspect',
          '--format',
          '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}',
          id,
        ])
        lastStatus = stdout.trim()
      } catch (error) {
        lastStatus = error instanceof Error ? error.message : String(error)
        await new Promise((resolve) => setTimeout(resolve, 500))
        continue
      }

      if (lastStatus === 'healthy') {
        return id
      }

      if (lastStatus === 'unhealthy') {
        throw new Error('container healthcheck reported unhealthy')
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 500))
  }

  throw new Error(`container did not become healthy: ${lastStatus}`)
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

async function encryptedPayload(plaintext) {
  const contextId = randomBytes(16).toString('hex')
  const keyBytes = randomBytes(32)
  const nonce = randomBytes(12)
  const key = await webcrypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
  ])
  const ciphertext = new Uint8Array(
    await webcrypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: new TextEncoder().encode(`onceveil:v1:${contextId}`),
        tagLength: 128,
      },
      key,
      new TextEncoder().encode(plaintext),
    ),
  )

  const payload = {
    contextId,
    version: 'v1',
    nonce: base64Url(nonce),
    ciphertext: base64Url(ciphertext),
  }

  return {
    payload,
    authorization: createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
  }
}

async function postJson(pathname, body, headers = {}) {
  return fetch(`${origin}${pathname}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Connection: 'close',
      ...headers,
    },
    body: JSON.stringify(body),
  })
}

async function assertMcpDisabledByDefault() {
  const response = await fetch(`${origin}/mcp`, {
    method: 'POST',
    headers: {
      Connection: 'close',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  })
  if (response.status !== 404) {
    throw new Error(`MCP must be disabled by default, got HTTP ${response.status}`)
  }
}

async function assertBrandingConfiguration() {
  const response = await fetch(origin, {
    headers: { Connection: 'close' },
  })
  const html = await response.text()
  if (
    !response.ok ||
    !html.includes('<title>CI Vault</title>') ||
    !html.includes('>CI Vault</h1>') ||
    !html.includes('src="/branding/ci-logo.svg"') ||
    !html.includes('href="/branding/ci-favicon.svg"') ||
    !html.includes('--brand-accent:#6E56CF')
  ) {
    throw new Error(`SSR branding configuration failed: ${response.status}`)
  }
}

async function createPersistedSecret() {
  const encrypted = await encryptedPayload('docker persistence and concurrency')
  const response = await postJson('/api/secrets', {
    payload: encrypted.payload,
    ownerKeyHash: randomBytes(32).toString('hex'),
  })
  const body = await response.json()

  if (response.status !== 201 || typeof body?.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) {
    throw new Error(`secret create failed: ${response.status} ${JSON.stringify(body)}`)
  }

  return {
    id: body.id,
    payload: encrypted.payload,
    authorization: encrypted.authorization,
  }
}

async function solveAltcha(path, verificationId) {
  const challengeUrl = new URL(`${origin}${path}`)
  challengeUrl.searchParams.set('verification', verificationId)
  const challengeResponse = await fetch(challengeUrl, {
    headers: {
      Connection: 'close',
      'X-Onceveil-Proof-Config': '1',
    },
  })
  const config = await challengeResponse.json()
  if (
    !challengeResponse.ok ||
    config?.provider !== 'altcha' ||
    typeof config?.challenge !== 'object' ||
    config.challenge === null
  ) {
    throw new Error(
      `ALTCHA challenge failed: ${challengeResponse.status} ${JSON.stringify(config)}`,
    )
  }

  const challenge = config.challenge
  const solution = await solveChallenge({ challenge, deriveKey })
  if (!solution) {
    throw new Error('ALTCHA challenge could not be solved')
  }

  return Buffer.from(JSON.stringify({ challenge, solution })).toString('base64')
}

async function revealPersistedSecret(secret) {
  const verificationId = randomBytes(16).toString('hex')
  const path = `/api/secrets/${secret.id}/reveal`

  const preparedResponse = await postJson(
    path,
    {
      authorization: secret.authorization,
      verificationId,
    },
    { 'X-Onceveil-Proof-Prepare': '1' },
  )
  const prepared = await preparedResponse.json()
  if (preparedResponse.status !== 201 || typeof prepared?.proof !== 'string') {
    throw new Error(
      `proof preparation failed: ${preparedResponse.status} ${JSON.stringify(prepared)}`,
    )
  }

  const invalidVerification = await postJson(
    path,
    { token: 'invalid-altcha-payload', verificationId },
    { 'X-Onceveil-Proof-Request': '1' },
  )
  if (invalidVerification.status !== 403) {
    throw new Error(
      `invalid ALTCHA verification returned ${invalidVerification.status} instead of 403`,
    )
  }

  const token = await solveAltcha(path, verificationId)
  const verificationResponse = await postJson(
    path,
    { token, verificationId },
    { 'X-Onceveil-Proof-Request': '1' },
  )
  if (verificationResponse.status !== 200) {
    throw new Error(`ALTCHA proof verification failed: ${verificationResponse.status}`)
  }

  const replayVerification = await postJson(
    path,
    { token, verificationId },
    { 'X-Onceveil-Proof-Request': '1' },
  )
  if (replayVerification.status !== 403) {
    throw new Error(
      `replayed ALTCHA verification returned ${replayVerification.status} instead of 403`,
    )
  }

  const reveal = () => postJson(path, { proof: prepared.proof }, { 'X-Onceveil-Reveal': '1' })

  const responses = await Promise.all([reveal(), reveal()])
  const statuses = responses.map((response) => response.status).sort((a, b) => a - b)
  if (statuses[0] !== 200 || statuses[1] !== 403) {
    throw new Error(`parallel reveal returned unexpected statuses: ${statuses.join(', ')}`)
  }

  const winner = responses.find((response) => response.status === 200)
  const payload = await winner.json()
  if (JSON.stringify(payload) !== JSON.stringify(secret.payload)) {
    throw new Error('winning reveal returned a different encrypted payload')
  }
}

async function assertNonRoot() {
  const { stdout } = await compose(['exec', '-T', 'onceveil', 'id', '-u'])
  if (stdout.trim() === '0') {
    throw new Error('Onceveil container must not run as root')
  }
}

try {
  await command('docker', ['compose', 'version'])
  await assertComposeDefaultsToAltcha()
  await assertTrustedNetworkNoneIsExplicitlyAvailable()

  await compose(['up', '--build', '-d', 'onceveil'])
  const firstContainer = await waitUntilHealthy()
  await assertNonRoot()
  await assertBrandingConfiguration()
  await assertMcpDisabledByDefault()

  const secret = await createPersistedSecret()

  await compose(['up', '-d', '--force-recreate', '--no-deps', 'onceveil'])
  const secondContainer = await waitUntilHealthy()
  if (secondContainer === firstContainer) {
    throw new Error('Docker persistence check did not recreate the container')
  }

  await assertNonRoot()
  await revealPersistedSecret(secret)

  console.log(
    'Docker Compose branding, MCP opt-in, ALTCHA, persistence and one-time reveal check passed',
  )
} finally {
  await compose(['down', '-v', '--remove-orphans']).catch(() => undefined)
}
