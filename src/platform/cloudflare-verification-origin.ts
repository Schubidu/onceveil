const PRODUCTION_CUSTOM_HOST = 'ots.schult.dev'
const PRODUCTION_WORKERS_HOST = 'onceveil.schult.workers.dev'
const PREVIEW_CUSTOM_SUFFIX = '.ots-preview.schult.dev'
const PREVIEW_WORKERS_SUFFIX = '-onceveil.schult.workers.dev'

export function pairedCloudflareVerificationOrigin(origin: string): string | undefined {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return undefined
  }

  if (url.protocol !== 'https:') {
    return undefined
  }

  const hostname = url.hostname.toLowerCase()
  if (hostname === PRODUCTION_CUSTOM_HOST) {
    return `https://${PRODUCTION_WORKERS_HOST}`
  }

  if (hostname === PRODUCTION_WORKERS_HOST) {
    return `https://${PRODUCTION_CUSTOM_HOST}`
  }

  if (hostname.endsWith(PREVIEW_CUSTOM_SUFFIX)) {
    const preview = hostname.slice(0, -PREVIEW_CUSTOM_SUFFIX.length)
    return preview ? `https://${preview}${PREVIEW_WORKERS_SUFFIX}` : undefined
  }

  if (hostname.endsWith(PREVIEW_WORKERS_SUFFIX)) {
    const preview = hostname.slice(0, -PREVIEW_WORKERS_SUFFIX.length)
    return preview ? `https://${preview}${PREVIEW_CUSTOM_SUFFIX}` : undefined
  }

  return undefined
}
