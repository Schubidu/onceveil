export interface RevealVerificationOriginConfig {
  appOrigin?: string
  verificationOrigin?: string
  previewAppOrigin?: string
  previewVerificationOrigin?: string
}

const PREVIEW_NAME_PATTERN = /^[a-z0-9-]+$/

function configuredOrigin(value: string | undefined): URL | undefined {
  if (!value) {
    return undefined
  }

  try {
    const url = new URL(value)
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== '/' ||
      url.search ||
      url.hash
    ) {
      return undefined
    }

    return url
  } catch {
    return undefined
  }
}

function pairedPreviewOrigin(
  currentOrigin: string,
  sourceBase: string | undefined,
  targetBase: string | undefined,
): string | undefined {
  const current = configuredOrigin(currentOrigin)
  const source = configuredOrigin(sourceBase)
  const target = configuredOrigin(targetBase)
  if (!current || !source || !target) {
    return undefined
  }

  const suffix = `.${source.hostname}`
  if (!current.hostname.endsWith(suffix)) {
    return undefined
  }

  const previewName = current.hostname.slice(0, -suffix.length)
  if (!PREVIEW_NAME_PATTERN.test(previewName)) {
    return undefined
  }

  const paired = `https://${previewName}.${target.hostname}`
  return paired === current.origin ? undefined : paired
}

export function verificationOriginForParent(
  parentOrigin: string,
  config: RevealVerificationOriginConfig,
): string | undefined {
  const parent = configuredOrigin(parentOrigin)
  const app = configuredOrigin(config.appOrigin)
  const verification = configuredOrigin(config.verificationOrigin)
  if (
    parent &&
    app &&
    verification &&
    parent.origin === app.origin &&
    verification.origin !== parent.origin
  ) {
    return verification.origin
  }

  return pairedPreviewOrigin(
    parentOrigin,
    config.previewAppOrigin,
    config.previewVerificationOrigin,
  )
}

export function parentOriginForVerification(
  verificationOrigin: string,
  config: RevealVerificationOriginConfig,
): string | undefined {
  const verification = configuredOrigin(verificationOrigin)
  const configuredVerification = configuredOrigin(config.verificationOrigin)
  const app = configuredOrigin(config.appOrigin)
  if (
    verification &&
    configuredVerification &&
    app &&
    verification.origin === configuredVerification.origin &&
    app.origin !== verification.origin
  ) {
    return app.origin
  }

  return pairedPreviewOrigin(
    verificationOrigin,
    config.previewVerificationOrigin,
    config.previewAppOrigin,
  )
}
