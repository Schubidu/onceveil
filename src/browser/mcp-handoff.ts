import {
  isValidMcpHandoffToken,
  type McpHandoffToken,
} from '../core/mcp-handoff'
import { isValidSecretId } from '../core/secret'
import type { FragmentHistory, FragmentLocation } from './secret-crypto'
import { revealAuthorizationFromFragment } from './secret-crypto'

const HANDOFF_VERSION = 'v1'

export function takeMcpHandoffToken(
  location: FragmentLocation,
  history: FragmentHistory,
): McpHandoffToken | undefined {
  const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
  if (!fragment) {
    return undefined
  }

  history.replaceState(history.state, '', `${location.pathname}${location.search}`)

  const [version, token, extra] = fragment.split('.')
  if (
    version !== HANDOFF_VERSION ||
    typeof token !== 'string' ||
    extra !== undefined ||
    !isValidMcpHandoffToken(token)
  ) {
    return undefined
  }

  return token
}

export function validOnceveilShareUrl(value: string, origin: string): string | undefined {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return undefined
  }

  if (url.origin !== origin || url.search !== '') {
    return undefined
  }

  const match = /^\/s\/([^/]+)$/.exec(url.pathname)
  if (!match) {
    return undefined
  }

  let secretId: string
  try {
    secretId = decodeURIComponent(match[1])
  } catch {
    return undefined
  }
  if (!isValidSecretId(secretId)) {
    return undefined
  }

  const fragment = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash
  try {
    revealAuthorizationFromFragment(fragment)
  } catch {
    return undefined
  }

  return url.toString()
}
