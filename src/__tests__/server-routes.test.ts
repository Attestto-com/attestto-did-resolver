/**
 * SOC-176 — the wiring layer, which nothing tested.
 *
 * Every module this server composes is well covered, and none of that proved
 * the composition worked. `server.ts` exported nothing and called `listen()` at
 * import, so no test could reach a route: whether CORS headers are ACTUALLY
 * attached to a response, whether the limiter ACTUALLY runs before the resolve
 * path, whether a degraded health check ACTUALLY sends 503, whether a
 * `deactivated` result ACTUALLY becomes a 200.
 *
 * That gap is not academic — it is precisely where this epic's defects lived.
 * `cors.ts` was correct and fully unit-tested while `cors-whitelist.json` was
 * never copied into the image, so the control had never executed in any built
 * artefact. No unit test could have caught it, and no unit test did.
 *
 * These tests drive the real handler over a real socket. Assertions are on
 * status codes and headers — the things a client sees — not on internals.
 */
import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

// The whitelist is read at module load, so the origin under test has to be one
// the shipped `cors-whitelist.json` actually contains. Read from the same file
// the server reads rather than hardcoded here: a test that asserted its own
// constant would keep passing after the file changed.
const { default: whitelist } = await import('../cors-whitelist.json', {
  with: { type: 'json' },
})
const ALLOWED_ORIGIN: string = (whitelist as { allowedOrigins: string[] }).allowedOrigins[0]

const { requestHandler } = await import('../server.js')

let server: Server
let base: string

before(async () => {
  server = createServer(requestHandler)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})

after(() => server.close())

/**
 * Each request gets a distinct forged client IP so the rate limiter — which is
 * shared process-wide — does not make one test's traffic throttle another's.
 * `TRUST_FORWARDED_FOR` is off, so this header does NOT actually change the
 * limiter's key; the counter is exercised honestly. The `ipSeed` exists only to
 * document intent if that default ever flips.
 */
let seq = 0
const get = (path: string, headers: Record<string, string> = {}) =>
  fetch(`${base}${path}`, { headers: { 'x-ip-seed': String(seq++), ...headers } })

describe('CORS is attached to real responses, not just computed', () => {
  test('an allowed Origin gets the header back', async () => {
    const res = await get('/health', { Origin: ALLOWED_ORIGIN })
    assert.equal(res.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN)
  })

  test('the response varies on Origin, so a cache cannot serve one to another', async () => {
    // Without `Vary: Origin`, an intermediary that cached the allowed response
    // would replay its ACAO header to a different origin. The header is
    // computed correctly in cors.ts either way — only this asserts it lands.
    const res = await get('/health', { Origin: ALLOWED_ORIGIN })
    assert.match(res.headers.get('vary') ?? '', /Origin/i)
  })

  test('a disallowed Origin is refused with 403 and gets no ACAO', async () => {
    const res = await get('/health', { Origin: 'https://evil.example' })
    assert.equal(res.status, 403)
    assert.equal(res.headers.get('access-control-allow-origin'), null)
  })

  test('a preflight from a disallowed Origin is 403, not 204', async () => {
    const res = await fetch(`${base}/1.0/identifiers/did:pki:cr:raiz-nacional`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' },
    })
    assert.equal(res.status, 403)
  })

  test('a request with no Origin at all is served', async () => {
    // curl, server-to-server, the Universal Resolver itself. A CORS check that
    // required an Origin would break every non-browser client.
    const res = await get('/health')
    assert.equal(res.headers.get('access-control-allow-origin'), null)
    assert.notEqual(res.status, 403)
  })
})

describe('/health reports its verdict over the wire', () => {
  test('the trust store never refreshed in-process, so health is degraded and 503', async () => {
    // No `start()` here, so no refresh has run: `source: 'baked'`,
    // `lastRefreshAt: null`. That is exactly the state the live instance is in,
    // and this is the assertion that would have caught it — health.test.ts
    // proves the verdict function, this proves the endpoint sends it.
    const res = await get('/health')
    assert.equal(res.status, 503)
    const body = (await res.json()) as { status: string; reasons: string[] }
    assert.equal(body.status, 'degraded')
    assert.ok(body.reasons.includes('trust-source-baked'))
    assert.ok(body.reasons.includes('no-successful-refresh'))
  })

  test('/ mirrors /health', async () => {
    const res = await get('/')
    assert.equal(res.status, 503)
  })
})

describe('resolution routes map results to the documented status codes', () => {
  test('a malformed DID is 400', async () => {
    const res = await get('/1.0/identifiers/did:pki:not%20a%20did')
    assert.equal(res.status, 400)
  })

  test('an unsupported method is 400 with methodNotSupported', async () => {
    const res = await get('/1.0/identifiers/did:example:123')
    assert.equal(res.status, 400)
    const body = (await res.json()) as { didResolutionMetadata: { error: string } }
    assert.equal(body.didResolutionMetadata.error, 'methodNotSupported')
  })

  test('an unknown did:pki DID is 404, and the body is a resolution result', async () => {
    const res = await get('/1.0/identifiers/did:pki:cr:no-such-authority')
    assert.equal(res.status, 404)
    const body = (await res.json()) as {
      didDocument: unknown
      didResolutionMetadata: { error: string; contentType?: string }
    }
    assert.equal(body.didDocument, null)
    assert.equal(body.didResolutionMetadata.error, 'notFound')
    // DID Resolution: an error result carries no contentType. Asserted here
    // because the shape is what a Universal Resolver client parses.
    assert.equal(body.didResolutionMetadata.contentType, undefined)
  })

  test('a DID URL with a fragment resolves rather than 400-ing', async () => {
    // The SOC-176 fix: `#key-1` used to make the whole identifier invalid.
    // Whatever the outcome, it must not be a syntax rejection.
    const res = await get('/1.0/identifiers/did:pki:cr:raiz-nacional%23key-1')
    assert.notEqual(res.status, 400)
  })

  test('an unknown path is 404', async () => {
    const res = await get('/nope')
    assert.equal(res.status, 404)
  })
})

describe('the admin surface is closed', () => {
  test('POST /admin/refresh without a bearer token is refused', async () => {
    const res = await fetch(`${base}/admin/refresh`, { method: 'POST' })
    assert.ok(
      res.status === 401 || res.status === 403 || res.status === 503,
      `unauthenticated refresh must not be accepted, got ${res.status}`,
    )
  })

  test('GET /admin/refresh is not a way in', async () => {
    // The auth check lives on the POST branch. A GET that fell through to a
    // handler would bypass it entirely.
    const res = await get('/admin/refresh')
    assert.equal(res.status, 404)
  })
})

describe('the rate limiter runs on the resolve path and not on health', () => {
  test('sustained resolve traffic eventually gets 429 with Retry-After', async () => {
    // Sequential, not parallel: the limiter is per-IP and every request here
    // shares one. The default is 30 requests per 10s, so 40 must trip it.
    let limited: Response | null = null
    for (let i = 0; i < 40 && !limited; i++) {
      const res = await get('/1.0/identifiers/did:pki:cr:no-such-authority')
      if (res.status === 429) limited = res
      else await res.arrayBuffer()
    }
    assert.ok(limited, 'the limiter never engaged on the public resolve path')
    assert.match(limited!.headers.get('retry-after') ?? '', /^\d+$/)
    await limited!.arrayBuffer()
  })

  test('/health is still served after the limiter has engaged', async () => {
    // Ordering matters and is asserted by running after the test above: the
    // health branch returns before the limiter is consulted. If that order ever
    // flips, uptime monitoring goes dark exactly when the resolver is busiest.
    const res = await get('/health')
    assert.notEqual(res.status, 429)
  })
})
