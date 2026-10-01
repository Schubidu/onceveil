function hasAsciiControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code <= 0x1f || code === 0x7f) {
      return true
    }
  }
  return false
}

export function resolvePublicOrigin(value: string | undefined): string | undefined {
  if (!value || value.trim() !== value || hasAsciiControlCharacter(value)) {
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
