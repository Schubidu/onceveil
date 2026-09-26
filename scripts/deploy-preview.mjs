import { spawn } from 'node:child_process'

const wranglerCommand = process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler'

function runPreview() {
  return new Promise((resolve, reject) => {
    const child = spawn(wranglerCommand, ['preview', '--ignore-base-config', '--json'], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'inherit'],
    })

    let stdout = ''
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })

    child.once('error', reject)
    child.once('close', (code) => {
      if (code !== 0) {
        reject(new Error(`wrangler preview failed with exit code ${code ?? 'unknown'}`))
        return
      }

      resolve(stdout.trim())
    })
  })
}

function previewUrls(output) {
  return [
    ...(Array.isArray(output?.deployment?.urls) ? output.deployment.urls : []),
    ...(Array.isArray(output?.preview?.urls) ? output.preview.urls : []),
    ...(Array.isArray(output?.deployment_urls) ? output.deployment_urls : []),
    ...(Array.isArray(output?.preview_urls) ? output.preview_urls : []),
  ].filter((value) => typeof value === 'string' && value.length > 0)
}

function selectReadinessOrigin(urls) {
  return urls.find((value) => new URL(value).hostname.endsWith('.workers.dev')) ?? urls[0]
}

async function checkReadiness(origin) {
  const readyUrl = new URL('/ready', origin)

  for (let attempt = 1; attempt <= 6; attempt += 1) {
    try {
      const response = await fetch(readyUrl, {
        signal: AbortSignal.timeout(10_000),
      })
      const body = await response.json().catch(() => null)

      if (response.ok && body?.status === 'ready' && body?.database === 'ok') {
        console.log(`Preview readiness passed at ${readyUrl.origin}`)
        return
      }

      if (body?.status === 'not_ready') {
        throw new Error(`Preview is not ready: ${JSON.stringify(body)}`)
      }

      if (attempt === 6) {
        throw new Error(
          `Preview readiness returned HTTP ${response.status}: ${JSON.stringify(body)}`,
        )
      }
    } catch (error) {
      if (
        error instanceof Error &&
        (error.message.startsWith('Preview is not ready:') ||
          error.message.startsWith('Preview readiness returned HTTP'))
      ) {
        throw error
      }

      if (attempt === 6) {
        throw error
      }

      await new Promise((resolve) => setTimeout(resolve, 2_000))
    }
  }
}

const stdout = await runPreview()
if (!stdout) {
  throw new Error('wrangler preview returned no JSON output')
}

let output
try {
  output = JSON.parse(stdout)
} catch (error) {
  throw new Error('wrangler preview returned invalid JSON output', { cause: error })
}

console.log(stdout)

const urls = previewUrls(output)
const origin = selectReadinessOrigin(urls)
if (!origin) {
  throw new Error('wrangler preview returned no Preview or deployment URL')
}

await checkReadiness(origin)
