/** Same-origin path-only redirect targets for login returnTo. */
export function safeReturnTo(value: unknown, fallback = '/'): string {
  if (typeof value !== 'string' || value.length === 0) return fallback

  // Reject absolute / scheme-relative URLs before URL parsing.
  if (value.startsWith('//') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value)) {
    return fallback
  }
  if (!value.startsWith('/')) return fallback

  try {
    const origin =
      typeof window !== 'undefined' && window.location?.origin
        ? window.location.origin
        : 'http://localhost'
    const parsed = new URL(value, origin)
    if (parsed.origin !== origin) return fallback
    const result = `${parsed.pathname}${parsed.search}${parsed.hash}`
    if (!result.startsWith('/') || result.startsWith('//')) return fallback
    return result
  } catch {
    return fallback
  }
}

export function returnToFromState(state: unknown): string | null {
  if (!state || typeof state !== 'object' || !('returnTo' in state)) return null
  const returnTo = (state as { returnTo: unknown }).returnTo
  if (typeof returnTo !== 'string') return null
  const safe = safeReturnTo(returnTo, '')
  return safe.length > 0 ? safe : null
}
