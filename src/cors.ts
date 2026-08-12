/**
 * CORS origin allowlisting — extracted from `server.ts` so it can be tested,
 * and rewritten to fail CLOSED.
 *
 * The previous version lived inline at module scope and swallowed every read
 * failure:
 *
 *     try   { allowedOrigins = JSON.parse(readFileSync(...)).allowedOrigins || [] }
 *     catch { allowedOrigins = process.env.NODE_ENV === 'production' ? [] : ['*'] }
 *
 * `tsc` emits no `.json`, the Dockerfile copies only `dist/`, and `NODE_ENV` is
 * set nowhere — so in every built image the read threw and the process ran with
 * `['*']`, reflecting any Origin back. The ten-entry whitelist, its `$schema`
 * and its "add new origins via PR" comment described a control that had never
 * executed. `SECURITY-AUDIT-2026-07-19.md:49` predicted exactly this.
 *
 * A misconfigured security control must stop the process, not widen it. There
 * is no fallback here on purpose.
 */

export interface CorsWhitelist {
  allowedOrigins?: unknown
}

/**
 * Parse and validate the origin allowlist. Throws — deliberately — on anything
 * that would leave the service running without a working control.
 *
 * `readFile` is injected so the failure paths are testable without touching the
 * filesystem; the caller supplies the real read.
 */
export function loadAllowedOrigins(readFile: () => string): string[] {
  let raw: string
  try {
    raw = readFile()
  } catch (err) {
    // No fallback. Booting unprotected is the defect.
    throw new Error(
      `cors-whitelist.json could not be read — refusing to start without an origin allowlist. ` +
        `It is read from the build output at runtime, so the Dockerfile must copy it into dist/. ` +
        `Cause: ${err instanceof Error ? err.message : String(err)}`,
    )
  }

  const parsed = JSON.parse(raw) as CorsWhitelist
  const origins = parsed.allowedOrigins

  if (!Array.isArray(origins) || origins.some((o) => typeof o !== 'string')) {
    throw new Error('cors-whitelist.json: allowedOrigins must be an array of strings')
  }
  if (origins.length === 0) {
    // An empty allowlist blocks every browser and protects nothing from
    // anything else. It is far more likely to be a packaging accident than an
    // intent, so it is refused rather than silently enforced.
    throw new Error('cors-whitelist.json: allowedOrigins is empty — an empty control is a missing control')
  }
  if (origins.includes('*')) {
    // The old code turned `*` into reflection of the caller's Origin rather
    // than emitting a literal `*` — unrestricted access wearing an allowlist's
    // clothes. If a deployment genuinely wants open CORS it should say so in
    // code, not through a wildcard in a data file.
    throw new Error('cors-whitelist.json: a wildcard origin is not accepted; list origins explicitly')
  }

  return origins as string[]
}

/**
 * The CORS headers for a request's Origin, or `null` when it is not allowed.
 *
 * Matching is exact and case-sensitive: an origin is a scheme+host+port triple,
 * and treating `HTTPS://VERIFY.ATTESTTO.COM` or
 * `https://verify.attestto.com.evil.com` as a match would defeat the list.
 *
 * A request with no `Origin` is not a CORS request and gets no headers — the
 * old code emitted `Access-Control-Allow-Origin: *` for it via `origin || '*'`.
 */
export function corsHeadersFor(
  origin: string | undefined,
  allowedOrigins: readonly string[],
): Record<string, string> | null {
  if (!origin) return null
  if (!allowedOrigins.includes(origin)) return null

  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
    'Access-Control-Max-Age': '86400',
    // The response body varies by Origin, so a shared cache must key on it.
    // Without this the allowlist is enforced at the server and defeated at the
    // CDN, which serves one origin's headers to another.
    Vary: 'Origin',
  }
}
