/**
 * Attestto DID Resolver — Unified Universal Resolver Driver
 *
 * Routes DID resolution requests to method-specific resolvers:
 *   did:pki:* → PKI resolver (national PKI bridge)
 *   did:sns:* → SNS resolver (Solana Name Service)
 *
 * Conforms to DIF Universal Resolver driver spec:
 *   GET /1.0/identifiers/{did} → W3C DID Resolution Result
 *
 * Environment variables:
 *   TRUST_STORE_PATH  — Path to attestto-trust/countries/ (for did:pki)
 *   SOLANA_RPC_URL    — Custom Solana RPC endpoint (for did:sns)
 *   PORT              — HTTP port (defaults to 8080)
 *   LOG_LEVEL         — "debug" | "info" | "warn" | "error" (defaults to "info")
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { TrustRegistry } from './registry.js'
import { DidPkiResolver } from './pki-resolver.js'
import { DidSnsResolver } from './sns-resolver.js'
import { CrlRevocationService } from './crl-revocation.js'
import { RefreshManager, type TrustState } from './trust-refresh.js'
import { checkBearer } from './admin-auth.js'
import { readBodyCapped, clientIp } from './http-utils.js'
import { RateLimiter, DEFAULT_RATE_LIMIT } from './rate-limit.js'
import { loadAllowedOrigins, corsHeadersFor } from './cors.js'
import { statusForResolution, resolutionError } from './resolution.js'
import { parseDidUrl } from './parser.js'
import { healthReport } from './health.js'
import { verifyPresentation } from './vp-verify.js'

const PORT = Number(process.env.PORT || 8080)
const LOG_LEVEL = process.env.LOG_LEVEL || 'info'
const TRUST_STORE = process.env.TRUST_STORE_PATH ?? join(dirname(fileURLToPath(import.meta.url)), '..', 'trust-store', 'countries')
const REFRESH_SECRET = process.env.REFRESH_SECRET

// ── Rate limiting ───────────────────────────────────────────────────
// Per-client-IP throttle for the public, unauthenticated surface. Defaults to
// 1 request per 5s per IP; /health and / (status) are exempt (see handleRequest).
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || DEFAULT_RATE_LIMIT.maxRequests)
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || DEFAULT_RATE_LIMIT.windowMs)
const rateLimiter = new RateLimiter({ windowMs: RATE_LIMIT_WINDOW_MS, maxRequests: RATE_LIMIT_MAX })

// `X-Forwarded-For` is caller-controlled. Behind Fly the edge sets
// `Fly-Client-IP`, which is preferred anyway, so this stays off unless a
// deployment knows a trusted proxy overwrites the header.
const TRUST_FORWARDED_FOR = process.env.TRUST_FORWARDED_FOR === 'true'

// ── Initialize resolvers ────────────────────────────────────────────

// Cold start from the baked snapshot — the resolver is never empty even if
// the first network refresh fails.
const bakedRegistry = new TrustRegistry(TRUST_STORE)
try {
  bakedRegistry.load()
} catch (err) {
  console.warn(`[did:pki] Baked trust store not loaded: ${err instanceof Error ? err.message : err}`)
}
const bakedPki = new DidPkiResolver(bakedRegistry)
const state: TrustState = {
  registry: bakedRegistry,
  pkiResolver: bakedPki,
  crl: new CrlRevocationService(TRUST_STORE),
  meta: { source: 'baked', version: 'baked', didCount: bakedPki.listDids().length, lastRefreshAt: null },
  tempDir: null,
}
const snsResolver = new DidSnsResolver()

const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS || 21_600_000) // 6h
const REFRESH_FLOOR_FRACTION = Number(process.env.REFRESH_FLOOR_FRACTION || 0.9)
const REFRESH_DEBOUNCE_MS = Number(process.env.REFRESH_DEBOUNCE_MS || 30_000)
const refreshManager = new RefreshManager(state, {
  floorFraction: REFRESH_FLOOR_FRACTION,
  debounceMs: REFRESH_DEBOUNCE_MS,
})

log('info', `[did:pki] Cold start: ${state.meta.didCount} DIDs from baked snapshot`)
log('info', `[did:sns] Solana RPC: ${process.env.SOLANA_RPC_URL || 'mainnet public (default)'}`)

// ── CORS ────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url))

/**
 * Loaded at boot, and NOT wrapped in a try/catch.
 *
 * The previous version fell back to `NODE_ENV === 'production' ? [] : ['*']` on
 * any read failure — and since `tsc` emits no `.json`, the Dockerfile copied
 * only `dist/`, and `NODE_ENV` was set nowhere, every built image ran with
 * `['*']` and reflected any Origin. The allowlist described a control that had
 * never executed.
 *
 * A throw here stops the process. That is the intended behaviour: a resolver
 * that cannot load its origin policy must not serve traffic pretending it has
 * one.
 */
const allowedOrigins = loadAllowedOrigins(() =>
  readFileSync(join(__dirname, 'cors-whitelist.json'), 'utf-8'),
)
log('info', `CORS: ${allowedOrigins.length} allowed origins`)

function setCorsHeaders(req: IncomingMessage, res: ServerResponse): boolean {
  const headers = corsHeadersFor(req.headers.origin, allowedOrigins)
  if (!headers) return false
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value)
  return true
}

// ── Logging ─────────────────────────────────────────────────────────

function log(level: string, message: string, data?: Record<string, unknown>) {
  const levels = ['debug', 'info', 'warn', 'error']
  if (levels.indexOf(level) < levels.indexOf(LOG_LEVEL)) return
  const entry = { timestamp: new Date().toISOString(), level, message, ...data }
  console.log(JSON.stringify(entry))
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  const json = JSON.stringify(body, null, 2)
  res.writeHead(status, {
    'Content-Type': 'application/did+ld+json',
    'Content-Length': Buffer.byteLength(json),
  })
  res.end(json)
}

/** Send a response with the standard application/json content type. */
function sendPlainJson(res: ServerResponse, status: number, body: unknown) {
  const json = JSON.stringify(body, null, 2)
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
  })
  res.end(json)
}

// ── Request handler ─────────────────────────────────────────────────

async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`)
  const method = req.method || 'GET'

  // CORS
  const corsAllowed = setCorsHeaders(req, res)
  if (method === 'OPTIONS') {
    res.writeHead(corsAllowed ? 204 : 403)
    res.end()
    return
  }
  if (!corsAllowed && req.headers.origin) {
    sendJson(res, 403, { error: 'Origin not allowed', origin: req.headers.origin })
    return
  }

  // Health check.
  //
  // The verdict is DERIVED from trust state (see health.ts), not asserted. This
  // used to return a hardcoded `status: 'ok'` alongside the very fields that
  // showed it was not — so every uptime monitor pointed here reported green
  // while the instance served baked trust data that had never refreshed.
  if (url.pathname === '/health' || url.pathname === '/') {
    const health = healthReport(state.meta, Date.now(), REFRESH_INTERVAL_MS)
    sendJson(res, health.httpStatus, {
      status: health.status,
      reasons: health.reasons,
      driver: 'attestto-did-resolver',
      version: '0.1.0',
      supportedMethods: ['pki', 'sns'],
      pkiDids: state.meta.didCount,
      trust: {
        source: state.meta.source,
        trustVersion: state.meta.version,
        didCount: state.meta.didCount,
        lastRefreshAt: state.meta.lastRefreshAt,
      },
    })
    return
  }

  // Rate limit — per client IP, 1 req / 5s by default. /health and / returned
  // above and are exempt so uptime checks and Fly health probes are never throttled.
  const ip = clientIp(req, { trustForwardedFor: TRUST_FORWARDED_FOR })
  const limit = rateLimiter.check(ip)
  if (!limit.allowed) {
    log('warn', 'Rate limited', { ip, path: url.pathname, retryAfterSec: limit.retryAfterSec })
    res.setHeader('Retry-After', String(limit.retryAfterSec))
    sendPlainJson(res, 429, {
      error: 'rateLimited',
      message: `Too many requests. Retry after ${limit.retryAfterSec}s.`,
      retryAfterSec: limit.retryAfterSec,
    })
    return
  }

  // Properties endpoint (DIF driver convention)
  if (url.pathname === '/1.0/properties') {
    sendJson(res, 200, {
      'driver-did-pki': {
        http: {
          pattern: '^did:pki:.+$',
          resolverUri: `http://localhost:${PORT}/1.0/identifiers/`,
          testIdentifiers: [
            'did:pki:cr:raiz-nacional',
            'did:pki:cr:sinpe:persona-fisica',
          ],
        },
        method: 'pki',
        implementation: 'Attestto did:pki Resolver',
        implementationUrl: 'https://github.com/Attestto-com/did-pki-resolver',
      },
      'driver-did-sns': {
        http: {
          pattern: '^did:sns:.+$',
          resolverUri: `http://localhost:${PORT}/1.0/identifiers/`,
          testIdentifiers: [
            'did:sns:bonfida',
            'did:sns:attestto',
            'did:sns:devnet:test.attestto',
          ],
        },
        method: 'sns',
        implementation: 'Attestto did:sns Resolver',
        implementationUrl: 'https://github.com/Attestto-com/attestto-did-resolver',
      },
    })
    return
  }

  // CRL-based revocation endpoint for CR Firma Digital (SINPE).
  // GET /revocation/cr/:ca  where :ca ∈ { sinpe-persona-fisica, sinpe-persona-juridica }
  const revocationMatch = url.pathname.match(/^\/revocation\/cr\/([a-z0-9-]+)$/)
  if (revocationMatch && method === 'GET') {
    const ca = revocationMatch[1]
    if (!CrlRevocationService.isSupported(ca)) {
      sendPlainJson(res, 404, {
        error: 'Unsupported CA',
        ca,
        supported: ['sinpe-persona-fisica', 'sinpe-persona-juridica'],
      })
      return
    }
    try {
      const result = await state.crl.getRevocation(ca)
      log('info', 'Revocation served', {
        ca,
        revoked: result.revokedSerials.length,
        signatureVerified: result.signatureVerified,
        stale: result.stale,
      })
      // Cache the (public, non-user-specific) list in the browser until the CRL's
      // own nextUpdate, so clients do not re-download the full list on every check.
      // Fall back to 1h when the CRL is stale or omits nextUpdate.
      const maxAge =
        result.nextUpdate && !result.stale
          ? Math.max(60, Math.floor((new Date(result.nextUpdate).getTime() - Date.now()) / 1000))
          : 3600
      res.setHeader('Cache-Control', `public, max-age=${maxAge}`)
      sendPlainJson(res, 200, result)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      log('warn', 'Revocation upstream failure', { ca, error: message })
      sendPlainJson(res, 502, { error: 'CRL fetch failed', ca, message })
    }
    return
  }

  // Authenticated manual/webhook refresh. POST /admin/refresh { "source": "npm" | "main" }
  if (url.pathname === '/admin/refresh' && method === 'POST') {
    const auth = checkBearer(req.headers.authorization, REFRESH_SECRET)
    if (!auth.ok) {
      sendPlainJson(res, auth.status, auth.status === 503
        ? { error: 'Refresh endpoint disabled (REFRESH_SECRET not set)' }
        : { error: 'Unauthorized' })
      return
    }
    let source: 'npm' | 'main' = 'npm'
    try {
      const raw = await readBodyCapped(req, 4096)
      if (raw.length) {
        const body = JSON.parse(raw.toString('utf-8'))
        if (body?.source === 'main' || body?.source === 'npm') source = body.source
      }
    } catch (err) {
      if (err instanceof RangeError) {
        sendPlainJson(res, 413, { error: 'Payload too large' })
        return
      }
      // Empty or malformed body → default source 'npm'.
    }
    refreshManager.refresh(source, 'webhook')
      .then((r) => log(r.ok ? 'info' : 'warn', `[did:pki] Webhook refresh: ${r.reason}`, { didCount: r.didCount }))
      .catch((err) => log('warn', `[did:pki] Webhook refresh threw: ${err instanceof Error ? err.message : err}`))
    sendPlainJson(res, 202, { accepted: true, source })
    return
  }

  // Presentation verification. POST /1.0/verify
  //   { verifiablePresentation, expectedChallenge, expectedDomain } → { valid, holder, errors }
  //
  // SOC-181: `@attestto/id-wallet-adapter` has posted here since it was written
  // and this route did not exist, so every DID login failed closed against
  // the 404 handler. The contract it states is in `id-wallet-adapter/src/verify.ts:277`.
  //
  // The route sits AFTER the rate limiter deliberately — it does public-key
  // work per request, so it is the most expensive unauthenticated surface on
  // this server and the one that least deserves an exemption.
  if (url.pathname === '/1.0/verify') {
    if (method !== 'POST') {
      res.setHeader('Allow', 'POST, OPTIONS')
      sendPlainJson(res, 405, { error: 'methodNotAllowed', message: 'POST a presentation to /1.0/verify' })
      return
    }
    let body: unknown
    try {
      // A presentation carries whole credentials, so the cap is larger than
      // /admin/refresh's 4 KiB. It is still a cap: parsing is the first thing
      // an unauthenticated caller can make this process do.
      const raw = await readBodyCapped(req, 256 * 1024)
      body = JSON.parse(raw.toString('utf-8'))
    } catch (error) {
      if (error instanceof RangeError) {
        sendPlainJson(res, 413, { error: 'payloadTooLarge', message: 'Presentation exceeds 256 KiB' })
        return
      }
      sendPlainJson(res, 400, { valid: false, holder: null, errors: [{ code: 'invalidRequest', message: 'Body is not valid JSON' }] })
      return
    }

    // The verifier reads the document generically (DID Core property names),
    // so it takes a plain object rather than either method's document type —
    // one verifier, both methods, no branch that can drift per method.
    const asDocument = (doc: unknown): Record<string, unknown> | null =>
      (doc as Record<string, unknown> | null | undefined) ?? null

    const result = await verifyPresentation(body, async (did) => {
      if (did.startsWith('did:pki:')) return asDocument(state.pkiResolver.resolve(did).didDocument)
      if (did.startsWith('did:sns:')) return asDocument((await snsResolver.resolve(did)).didDocument)
      // Any other method is not resolvable by this server, so we cannot say
      // whose key signed. Returning null makes that a verification failure
      // rather than an exception.
      return null
    })

    log(result.valid ? 'info' : 'warn', 'Presentation verification', {
      holder: result.holder,
      valid: result.valid,
      // The code, never the message: messages name the expected values.
      error: result.errors[0]?.code,
    })

    // 200 with `valid: false` — the request was well-formed and the answer is
    // no. The adapter reads `res.ok` before the body, so answering 4xx for a
    // failed verification would be indistinguishable from the missing route
    // this ticket exists to fix.
    sendPlainJson(res, 200, result)
    return
  }

  // DID Resolution endpoint — route by method
  const identifierMatch = url.pathname.match(/^\/1\.0\/identifiers\/(.+)$/)
  if (identifierMatch && method === 'GET') {
    // A malformed percent-escape throws URIError. Unguarded, it fell through to
    // the process-wide catch and answered 500 `internalError` for what is a
    // client typo — and, once the rate limiter refunds on that code, composed
    // into an unmetered retry loop. `attestto-trust`'s cert pages interpolate a
    // DID into this URL unencoded, so this is reachable by accident.
    let rawIdentifier: string
    try {
      rawIdentifier = decodeURIComponent(identifierMatch[1])
    } catch {
      sendJson(res, 400, resolutionError('invalidDid', 'Malformed percent-encoding in identifier'))
      return
    }

    // Accept a DID URL, not only a bare DID. `did:pki:cr:sinpe:persona-fisica#key-1`
    // is the shape of a `kid` read straight out of a JWS header — the most
    // natural thing a consumer holds — and used to come back invalidDid.
    const didUrl = parseDidUrl(rawIdentifier)
    if (!didUrl) {
      sendJson(res, 400, resolutionError('invalidDid', `Not a DID: ${rawIdentifier}`))
      return
    }
    const did = didUrl.did

    log('info', 'Resolving DID', { did })
    const startTime = Date.now()

    let result: any

    if (did.startsWith('did:pki:')) {
      result = state.pkiResolver.resolve(did)
    } else if (did.startsWith('did:sns:')) {
      result = await snsResolver.resolve(did)
    } else {
      sendJson(res, 400, {
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: null,
        didResolutionMetadata: {
          error: 'methodNotSupported',
          errorMessage: `This resolver supports did:pki and did:sns, got: ${did}`,
        },
        didDocumentMetadata: {},
      })
      return
    }

    const duration = Date.now() - startTime
    const hasError = result.didResolutionMetadata?.error

    // A transient failure (cert couldn't be parsed, upstream RPC hiccup) surfaces
    // as `internalError`. Unlike notFound/invalidDid — which are the caller's
    // fault and permanent — this is worth an immediate retry. Mirror the way
    // transient TLS/SSL errors are retried: hand back the rate-limit token so the
    // retry isn't throttled, keep the W3C resolution shape (200, null document),
    // flag it retriable, and tell the caller to retry now (Retry-After: 0).
    // A transient upstream failure is worth an immediate retry, so the caller
    // gets its rate-limit token back and a `Retry-After: 0`. But the STATUS
    // must still say failure: this used to answer 200, and every DIF consumer
    // here gates on `res.ok`, so a dead RPC read as a successful resolution of
    // a null document.
    if (hasError === 'internalError') {
      rateLimiter.refund(ip)
      log('warn', 'Resolution transient error — inviting immediate retry', { did, duration, ip })
      result.didResolutionMetadata = { ...result.didResolutionMetadata, retriable: true }
      res.setHeader('Retry-After', '0')
    }

    const status = statusForResolution(hasError)

    log(
      hasError ? 'warn' : 'info',
      hasError ? 'Resolution failed' : 'Resolution successful',
      { did, duration, error: hasError }
    )

    sendJson(res, status, result)
    return
  }

  // List resolvable did:pki DIDs
  if (url.pathname === '/1.0/identifiers' && method === 'GET') {
    sendJson(res, 200, { pkiDids: state.pkiResolver.listDids() })
    return
  }

  sendJson(res, 404, { error: 'Not found', path: url.pathname })
}

// ── Server ──────────────────────────────────────────────────────────

/**
 * The request handler, exported so it can be tested.
 *
 * Every route in this file was previously unreachable from a test: the module
 * exported nothing, called `server.listen()` at import, and fired a network
 * refresh on the same tick. So the modules underneath were well covered while
 * the WIRING — whether CORS headers are actually attached, whether the limiter
 * actually runs before the resolve path, whether a degraded health check
 * actually sends 503 — was asserted nowhere. That is the layer the defects in
 * this epic lived in: `cors-whitelist.json` was never copied into the image,
 * and no unit test could have noticed.
 */
export const requestHandler = async (req: IncomingMessage, res: ServerResponse) => {
  try {
    await handleRequest(req, res)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error'
    log('error', 'Unhandled error', { error: message })
    sendJson(res, 500, {
      '@context': 'https://w3id.org/did-resolution/v1',
      didDocument: null,
      didResolutionMetadata: { error: 'internalError', errorMessage: message },
      didDocumentMetadata: {},
    })
  }
}

/**
 * Bind the port and start the refresh timers.
 *
 * Split from module scope so importing this file has no side effects. It used
 * to `listen()` and fire a network refresh on import, which is why nothing
 * could import it — and therefore why no route was ever tested.
 */
export function start() {
  const server = createServer(requestHandler)

  server.listen(PORT, () => {
    log('info', `Attestto DID Resolver listening on port ${PORT}`, {
      methods: ['did:pki', 'did:sns'],
      pkiDids: state.meta.didCount,
    })
  })

  // Pull the latest published trust data shortly after boot (non-blocking), then
  // on a fixed interval. Failures are logged and leave the baked snapshot in place.
  refreshManager.refresh('npm', 'startup')
    .then((r) => log(r.ok ? 'info' : 'warn', `[did:pki] Startup refresh: ${r.reason}`, { didCount: r.didCount }))
    .catch((err) => log('warn', `[did:pki] Startup refresh threw: ${err instanceof Error ? err.message : err}`))

  setInterval(() => {
    refreshManager.refresh('npm', 'scheduled')
      .then((r) => log(r.ok ? 'info' : 'warn', `[did:pki] Scheduled refresh: ${r.reason}`, { didCount: r.didCount }))
      .catch((err) => log('warn', `[did:pki] Scheduled refresh threw: ${err instanceof Error ? err.message : err}`))
  }, REFRESH_INTERVAL_MS).unref()

  // Periodically drop expired rate-limit windows so the map stays bounded.
  setInterval(() => rateLimiter.prune(), Math.max(RATE_LIMIT_WINDOW_MS, 60_000)).unref()

  return server
}

// Start only when run as the entrypoint — `node dist/server.js` (the Dockerfile
// CMD) and `tsx src/server.ts` both satisfy this; an `import` does not.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start()
}
