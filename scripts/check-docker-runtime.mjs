import { execFile } from 'node:child_process'
import { createHash, randomBytes, webcrypto } from 'node:crypto'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const projectName = `onceveil-ci-${process.pid}`
const port = 32_000 + (process.pid % 1_000)
const origin = `http://127.0.0.1:${port}`

const composeEnv = {
  ...process.env,
  COMPOSE_PROJECT_NAME: projectName,
  ONCEVEIL_BIND_ADDRESS: '127.0.0.1',
  ONCEVEIL_PORT: String(port),
  ONCEVEIL_REVEAL_PROTECTION: 'none',
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

async function assertComposeFailsClosed() {
  const env = { ...composeEnv }
  delete env.ONCEVEIL_REVEAL_PROTECTION

  try {
    await compose(['config'], env)
  } catch {
    return
  }

  throw new Error('docker compose config must fail without explicit reveal protection')
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
        if (lastStatus === 'healthy') {
          return id
        }

        if (lastStatus === 'unhealthy') {
          throw new Error('container healthcheck reported unhealthy')
        }
      } catch (error) {
        lastStatus = error instanceof Error ? error.message : String(error)
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

  const verificationResponse = await postJson(
    path,
    { verificationId },
    { 'X-Onceveil-Proof-Request': '1' },
  )
  if (verificationResponse.status !== 200) {
    throw new Error(`proof verification failed: ${verificationResponse.status}`)
  }

  const reveal = () =>
    postJson(path, { proof: prepared.proof }, { 'X-Onceveil-Reveal': '1' })

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
  await assertComposeFailsClosed()

  await compose(['up', '--build', '-d', 'onceveil'])
  const firstContainer = await waitUntilHealthy()
  await assertNonRoot()

  const secret = await createPersistedSecret()

  await compose(['up', '-d', '--force-recreate', '--no-deps', 'onceveil'])
  const secondContainer = await waitUntilHealthy()
  if (secondContainer === firstContainer) {
    throw new Error('Docker persistence check did not recreate the container')
  }

  await assertNonRoot()
  await revealPersistedSecret(secret)

  console.log('Docker Compose persistence and one-time reveal check passed')
} finally {
  await compose(['down', '-v', '--remove-orphans']).catch(() => undefined)
}
