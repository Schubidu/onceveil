type SafeLogValue = string | number | boolean | readonly string[]

const SAFE_LOG_FIELDS = new Set([
  'actionMatches',
  'actual',
  'cdataMatches',
  'diagnostic',
  'errorCodes',
  'expected',
  'hostnameMatches',
  'name',
  'stage',
  'status',
  'success',
])

export function safeLogFields(fields: Record<string, unknown>): Record<string, SafeLogValue> {
  const safe: Record<string, SafeLogValue> = {}

  for (const [key, value] of Object.entries(fields)) {
    if (!SAFE_LOG_FIELDS.has(key)) {
      continue
    }

    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      (Array.isArray(value) && value.every((item) => typeof item === 'string'))
    ) {
      safe[key] = value
    }
  }

  return safe
}

export function logRuntimeError(
  event: string,
  error: unknown,
  fields: Record<string, unknown> = {},
): void {
  console.error(event, {
    name: error instanceof Error ? error.name : 'UnknownError',
    ...safeLogFields(fields),
  })
}

export function logRuntimeWarning(event: string, fields: Record<string, unknown> = {}): void {
  const safe = safeLogFields(fields)
  if (Object.keys(safe).length === 0) {
    console.warn(event)
    return
  }

  console.warn(event, safe)
}
