import type { McpRuntime } from './request-context'

export interface McpEnvironment {
  enabled?: string
  authToken?: string
  storageKey?: string
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

function validAuthToken(value: string | undefined): value is string {
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

  if (!validAuthToken(environment.authToken) || !HEX_KEY_PATTERN.test(environment.storageKey ?? '')) {
    return { status: 'unavailable' }
  }

  return {
    status: 'enabled',
    authToken: environment.authToken,
    storageKey: hexBytes(environment.storageKey as string),
  }
}
