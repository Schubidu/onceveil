import {
  isValidOwnerCapability,
  OWNER_CAPABILITY_VERSION,
  type OwnerCapability,
} from '../core/owner-capability'
import type { SecretId } from '../core/secret'
import type { FragmentHistory, FragmentLocation } from './secret-crypto'

export function ownerPath(id: SecretId, capability: OwnerCapability): string {
  return `/o/${encodeURIComponent(id)}#${OWNER_CAPABILITY_VERSION}.${capability}`
}

export function takeOwnerCapability(
  location: FragmentLocation,
  history: FragmentHistory,
): OwnerCapability | undefined {
  const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
  if (!fragment) {
    return undefined
  }

  history.replaceState(history.state, '', `${location.pathname}${location.search}`)

  const [version, capability, extra] = fragment.split('.')
  if (
    version !== OWNER_CAPABILITY_VERSION ||
    typeof capability !== 'string' ||
    extra !== undefined ||
    !isValidOwnerCapability(capability)
  ) {
    return undefined
  }

  return capability
}
