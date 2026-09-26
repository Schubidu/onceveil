import { spawn } from 'node:child_process'

const wranglerCommand = process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler'

function runPreview() {
  return new Promise((resolve, reject) => {
    const args = ['preview', '--ignore-base-config', '--json']
    if (process.env.WORKERS_CI_BRANCH) {
      args.push('--name', process.env.WORKERS_CI_BRANCH)
    }

    const child = spawn(wranglerCommand, args, {
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
    ...(Array.isArray(output?.preview?.urls) ? output.preview.urls : []),
    ...(Array.isArray(output?.deployment?.urls) ? output.deployment.urls : []),
    ...(Array.isArray(output?.preview_urls) ? output.preview_urls : []),
    ...(Array.isArray(output?.deployment_urls) ? output.deployment_urls : []),
  ].filter((value) => typeof value === 'string' && value.length > 0)
}

async function checkReadiness(origin) {
  const readyUrl = new URL('/ready', origin)
  let lastResult = 'no response'

  for (let attempt = 1; attempt <= 8; attempt += 1) {
    try {
      const response = await fetch(readyUrl, {
        signal: AbortSignal.timeout(10_000),
      })
      const body = await response.json().catch(() => null)
      lastResult = `HTTP ${response.status}: ${JSON.stringify(body)}`

      if (response.ok && body?.status === 'ready' && body?.database === 'ok') {
        console.log(`Preview readiness passed at ${readyUrl.origin}`)
        return
      }
    } catch (error) {
      lastResult = error instanceof Error ? error.message : String(error)
    }

    if (attempt < 8) {
      await new Promise((resolve) => setTimeout(resolve, 2_000))
    }
  }

  throw new Error(`Preview readiness failed at ${readyUrl.origin}: ${lastResult}`)
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

const urls = [...new Set(previewUrls(output))]
if (urls.length === 0) {
  throw new Error('wrangler preview returned no Preview or deployment URL')
}

for (const url of urls) {
  await checkReadiness(url)
}
