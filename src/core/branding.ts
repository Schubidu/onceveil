import { PROJECT_NAME } from './project'

export interface BrandingConfig {
  name: string
  logo?: string
  favicon?: string
  theme: {
    accent: string
  }
}

export interface BrandingEnvironment {
  name?: string
  logo?: string
  favicon?: string
  accent?: string
}

export const DEFAULT_BRANDING: BrandingConfig = {
  name: PROJECT_NAME,
  theme: {
    accent: '#f0f6fc',
  },
}

const MAX_NAME_LENGTH = 80
const MAX_ASSET_PATH_LENGTH = 2_048
const ACCENT_PATTERN = /^#[0-9a-fA-F]{6}$/
const MARKUP_CHARACTERS = /[<>]/

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127
  })
}
const ASSET_BASE = 'https://onceveil.invalid'

function safeName(value: unknown): string {
  if (typeof value !== 'string') {
    return DEFAULT_BRANDING.name
  }

  const normalized = value.trim()
  if (
    normalized.length === 0 ||
    normalized.length > MAX_NAME_LENGTH ||
    hasControlCharacters(normalized) ||
    MARKUP_CHARACTERS.test(normalized)
  ) {
    return DEFAULT_BRANDING.name
  }

  return normalized
}

function safeAssetPath(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  const normalized = value.trim()
  if (normalized.length === 0 || normalized.length > MAX_ASSET_PATH_LENGTH) {
    return undefined
  }

  try {
    const url = new URL(normalized, ASSET_BASE)
    if (url.origin !== ASSET_BASE || !normalized.startsWith('/') || normalized.startsWith('//')) {
      return undefined
    }

    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return undefined
  }
}

function safeAccent(value: unknown): string {
  return typeof value === 'string' && ACCENT_PATTERN.test(value)
    ? value
    : DEFAULT_BRANDING.theme.accent
}

export function parseBrandingConfig(value: unknown): BrandingConfig {
  const input = typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {}
  const theme =
    typeof input.theme === 'object' && input.theme !== null
      ? (input.theme as Record<string, unknown>)
      : {}

  const logo = safeAssetPath(input.logo)
  const favicon = safeAssetPath(input.favicon)

  return {
    name: safeName(input.name),
    ...(logo ? { logo } : {}),
    ...(favicon ? { favicon } : {}),
    theme: {
      accent: safeAccent(theme.accent),
    },
  }
}

export function resolveBrandingConfig(environment: BrandingEnvironment = {}): BrandingConfig {
  return parseBrandingConfig({
    name: environment.name,
    logo: environment.logo,
    favicon: environment.favicon,
    theme: {
      accent: environment.accent,
    },
  })
}
