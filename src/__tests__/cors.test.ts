/**
 * SOC-175 — the CORS whitelist has never been active in a built image.
 *
 * Three facts composed into a total bypass:
 *
 *   1. `src/cors-whitelist.json` is read at runtime with `readFileSync`, but
 *      `tsc` emits only `.js`/`.d.ts` — `find dist -name '*.json'` is empty.
 *   2. `Dockerfile` copies only `dist/`, so the file is not in the image.
 *   3. the read therefore throws, and the catch fell back to
 *      `NODE_ENV === 'production' ? [] : ['*']` — while `NODE_ENV` is set
 *      nowhere: not in the Dockerfile, not in fly.toml, not in code.
 *
 * So `allowedOrigins` was `['*']` and every Origin was reflected verbatim.
 * Verified against the deployed instance: `Origin: https://evil.example.com`
 * came back in `access-control-allow-origin`.
 *
 * `SECURITY-AUDIT-2026-07-19.md:49` predicted this exact failure mode — "a
 * packaging error that drops the JSON silently widens CORS" — and nobody
 * checked it against the build. The audit records the control as present.
 *
 * A control that fails OPEN when misconfigured is worse than no control: it
 * documents a protection that does not exist.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadAllowedOrigins, corsHeadersFor } from '../cors.js'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

describe('the whitelist fails CLOSED, and loudly', () => {
  test('a missing whitelist throws rather than defaulting to anything', () => {
    // The old behaviour returned ['*'] and carried on. Booting with a
    // permissive default is the failure this ticket exists to remove: the
    // process must not start rather than start unprotected.
    assert.throws(
      () =>
        loadAllowedOrigins(() => {
          throw new Error('ENOENT')
        }),
      /cors-whitelist/i,
    )
  })

  test('an empty allowlist throws — an empty control is a missing control', () => {
    assert.throws(() => loadAllowedOrigins(() => JSON.stringify({ allowedOrigins: [] })), /empty/i)
  })

  test('malformed JSON throws', () => {
    assert.throws(() => loadAllowedOrigins(() => '{ not json'))
  })

  test('a wildcard entry is refused outright', () => {
    // `*` reflected the caller's Origin verbatim rather than emitting `*`,
    // which is unrestricted reflection wearing an allowlist's clothes.
    assert.throws(() => loadAllowedOrigins(() => JSON.stringify({ allowedOrigins: ['*'] })), /wildcard/i)
  })

  test('a well-formed whitelist loads', () => {
    const origins = loadAllowedOrigins(() =>
      JSON.stringify({ allowedOrigins: ['https://verify.attestto.com'] }),
    )
    assert.deepEqual(origins, ['https://verify.attestto.com'])
  })
})

describe('only listed origins are reflected', () => {
  const allowed = ['https://verify.attestto.com']

  test('a disallowed origin gets no Access-Control-Allow-Origin', () => {
    assert.equal(corsHeadersFor('https://evil.example.com', allowed), null)
  })

  test('an allowed origin is reflected, with Vary: Origin', () => {
    const headers = corsHeadersFor('https://verify.attestto.com', allowed)
    assert.ok(headers)
    assert.equal(headers['Access-Control-Allow-Origin'], 'https://verify.attestto.com')
    // Without Vary, a shared cache can serve one origin's ACAO header to
    // another — the allowlist survives the server and dies in the CDN.
    assert.equal(headers['Vary'], 'Origin')
  })

  test('a request with no Origin is not treated as an allowed one', () => {
    // The old code did `res.setHeader('Access-Control-Allow-Origin', origin || '*')`,
    // so an Origin-less request produced a wildcard header.
    assert.equal(corsHeadersFor('', allowed), null)
    assert.equal(corsHeadersFor(undefined, allowed), null)
  })

  test('matching is exact — no prefix or suffix games', () => {
    assert.equal(corsHeadersFor('https://verify.attestto.com.evil.com', allowed), null)
    assert.equal(corsHeadersFor('https://evil.com/https://verify.attestto.com', allowed), null)
    assert.equal(corsHeadersFor('HTTPS://VERIFY.ATTESTTO.COM', allowed), null)
  })
})

describe('the whitelist reaches the built image', () => {
  // The packaging assertion. Everything above is correct and useless if the
  // file is not in `dist/` at runtime — which is precisely how this control
  // came to be decorative.
  test('the Dockerfile copies the whitelist into dist/', () => {
    const dockerfile = readFileSync(join(repoRoot, 'Dockerfile'), 'utf-8')
    assert.match(
      dockerfile,
      /COPY\s+src\/cors-whitelist\.json\s+\.\/dist\//,
      'the whitelist is read from dist/ at runtime and tsc does not emit .json',
    )
  })

  test('the whitelist is real, non-empty JSON with no wildcard', () => {
    const raw = readFileSync(join(repoRoot, 'src', 'cors-whitelist.json'), 'utf-8')
    const origins = loadAllowedOrigins(() => raw)
    assert.ok(origins.length > 0)
    for (const o of origins) assert.match(o, /^https?:\/\//, `${o} is not an origin`)
  })
})
