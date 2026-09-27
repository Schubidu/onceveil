const PRODUCTION_PARENT_HOST = 'ots.schult.dev'
const PRODUCTION_VERIFICATION_HOST = 'onceveil.schult.workers.dev'
const PREVIEW_PARENT_SUFFIX = '.ots-preview.schult.dev'
const PREVIEW_VERIFICATION_SUFFIX = '-onceveil.schult.workers.dev'
const PREVIEW_NAME_PATTERN = /^[a-z0-9-]+$/

function httpsOrigin(hostname: string): string {
  return `https://${hostname}`
}

export function verificationOriginForParent(parentOrigin: string): string | undefined {
  const url = new URL(parentOrigin)
  if (url.protocol !== 'https:' || url.port) {
    return undefined
  }

  if (url.hostname === PRODUCTION_PARENT_HOST) {
    return httpsOrigin(PRODUCTION_VERIFICATION_HOST)
  }

  if (url.hostname.endsWith(PREVIEW_PARENT_SUFFIX)) {
    const previewName = url.hostname.slice(0, -PREVIEW_PARENT_SUFFIX.length)
    if (PREVIEW_NAME_PATTERN.test(previewName)) {
      return httpsOrigin(`${previewName}${PREVIEW_VERIFICATION_SUFFIX}`)
    }
  }

  return undefined
}

export function parentOriginForVerification(
  verificationOrigin: string,
): string | undefined {
  const url = new URL(verificationOrigin)
  if (url.protocol !== 'https:' || url.port) {
    return undefined
  }

  if (url.hostname === PRODUCTION_VERIFICATION_HOST) {
    return httpsOrigin(PRODUCTION_PARENT_HOST)
  }

  if (url.hostname.endsWith(PREVIEW_VERIFICATION_SUFFIX)) {
    const previewName = url.hostname.slice(0, -PREVIEW_VERIFICATION_SUFFIX.length)
    if (PREVIEW_NAME_PATTERN.test(previewName)) {
      return httpsOrigin(`${previewName}${PREVIEW_PARENT_SUFFIX}`)
    }
  }

  return undefined
}
