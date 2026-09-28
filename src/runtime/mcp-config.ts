import type { McpRuntime } from './request-context'

export interface McpEnvironment {
  enabled?: string
  authToken?: string
  storageKey?: string
  publicOrigin?: string
}

const HEX_KEY_PATTERN = /^[0-9a-fA-F]{64}$/
const MIN_AUTH_TOKEN_LENGTH = 32
const MAX_AUTH_TOKEN_LENGTH = 512

function hexBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function validPublicOrigin(value: string | undefined): string | undefined {
  if (!value || value.trim() !== value) {
    return undefined
  }

  try {
    const url = new URL(value)
    const loopback =
      url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]'
    if (
      (url.protocol !== 'https:' && !(loopback && url.protocol === 'http:')) ||
      url.username ||
      url.password ||
      url.pathname !== '/' ||
      url.search ||
      url.hash
    ) {
      return undefined
    }

    return url.origin
  } catch {
    return undefined
  }
}

export function isValidMcpAuthToken(value: string | undefined): value is string {
  return (
    typeof value === 'string' &&
    value.length >= MIN_AUTH_TOKEN_LENGTH &&
    value.length <= MAX_AUTH_TOKEN_LENGTH &&
    value.trim() === value
  )
}

export function resolveMcpRuntime(
  enabled: string | undefined,
  environment: McpEnvironment = {},
): McpRuntime {
  if (enabled === undefined || enabled === '' || enabled === 'false') {
    return { status: 'disabled' }
  }

  if (enabled !== 'true') {
    return { status: 'unavailable' }
  }

  const publicOrigin = validPublicOrigin(environment.publicOrigin)
  if (
    !isValidMcpAuthToken(environment.authToken) ||
    !HEX_KEY_PATTERN.test(environment.storageKey ?? '') ||
    !publicOrigin
  ) {
    return { status: 'unavailable' }
  }

  return {
    status: 'enabled',
    authToken: environment.authToken,
    storageKey: hexBytes(environment.storageKey as string),
    publicOrigin,
  }
}
