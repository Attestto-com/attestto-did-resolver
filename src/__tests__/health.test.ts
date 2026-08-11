/**
 * SOC-176 — a health endpoint that cannot report ill health.
 *
 * `/health` returned a hardcoded `status: 'ok'` and always HTTP 200. It
 * reported `source` and `lastRefreshAt` in the body, so the facts were on
 * screen — but nothing derived a verdict from them, which means every uptime
 * monitor pointed at this endpoint has been reporting green while the live
 * instance serves `source: "baked"` with `lastRefreshAt: null`, i.e. the
 * published trust data has never loaded and the resolver is answering from
 * whatever was in the image.
 *
 * This is the vacuous-control shape exactly: a control that exists, looks like
 * it covers the invariant, and cannot fail. The test that matters is not "does
 * /health return ok" — it is "is there an input for which /health does NOT".
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { healthReport, type TrustMeta } from '../health.js'

const HOUR = 3_600_000
const NOW = 1_760_000_000_000
const REFRESH_INTERVAL = 6 * HOUR

const healthy: TrustMeta = {
  source: 'npm',
  version: '1.4.0',
  didCount: 42,
  lastRefreshAt: new Date(NOW - HOUR).toISOString(),
}

const report = (meta: Partial<TrustMeta>) =>
  healthReport({ ...healthy, ...meta }, NOW, REFRESH_INTERVAL)

describe('a healthy resolver reports ok', () => {
  test('fresh npm trust data with DIDs indexed', () => {
    const r = report({})
    assert.equal(r.status, 'ok')
    assert.equal(r.httpStatus, 200)
    assert.deepEqual(r.reasons, [])
  })
})

describe('the states that made the live instance green while it was not', () => {
  test('serving baked data is degraded', () => {
    // The exact condition observed live: the image's baked snapshot, because
    // the startup refresh never succeeded.
    const r = report({ source: 'baked' })
    assert.equal(r.status, 'degraded')
    assert.ok(r.reasons.includes('trust-source-baked'))
  })

  test('no successful refresh, ever, is degraded', () => {
    const r = report({ lastRefreshAt: null })
    assert.equal(r.status, 'degraded')
    assert.ok(r.reasons.includes('no-successful-refresh'))
  })

  test('a refresh older than two intervals is degraded', () => {
    // Two intervals, not one: a single missed run is a transient npm blip and
    // must not page anyone. Two means the timer itself has stopped — which is
    // the failure `setInterval(...).unref()` on a machine Fly stops at idle is
    // most likely to have.
    const r = report({ lastRefreshAt: new Date(NOW - 2 * REFRESH_INTERVAL - 1000).toISOString() })
    assert.equal(r.status, 'degraded')
    assert.ok(r.reasons.includes('refresh-stale'))
  })

  test('a refresh one interval old is still ok', () => {
    // The control for the rule above. A threshold that trips on the normal
    // cadence is a threshold that gets muted.
    const r = report({ lastRefreshAt: new Date(NOW - REFRESH_INTERVAL - 1000).toISOString() })
    assert.equal(r.status, 'ok')
  })

  test('an empty registry is degraded', () => {
    // A resolver with zero DIDs answers notFound to every did:pki query. That
    // is indistinguishable, from outside, from "the DID does not exist" — so it
    // has to be visible here or it is not visible anywhere.
    const r = report({ didCount: 0 })
    assert.equal(r.status, 'degraded')
    assert.ok(r.reasons.includes('no-dids-indexed'))
  })

  test('an unparseable lastRefreshAt is degraded, not ok', () => {
    // Garbage in a timestamp must not read as freshness. `Date.parse` returns
    // NaN and every comparison against NaN is false, which is the classic way
    // a staleness check silently passes.
    const r = report({ lastRefreshAt: 'not-a-date' })
    assert.equal(r.status, 'degraded')
    assert.ok(r.reasons.includes('refresh-stale'))
  })
})

describe('degradation is reported in a way something can act on', () => {
  test('degraded is HTTP 503, not 200', () => {
    // The whole point. A body field nobody parses is what we already had.
    //
    // Safe here because `fly.toml` declares no [[checks]] block — Fly's default
    // TCP check does not read this endpoint, so a 503 does not cycle machines.
    // If a [[checks]] http_check is ever added pointing at /health, revisit
    // this: a stale-trust condition would then restart-loop the app.
    assert.equal(report({ source: 'baked' }).httpStatus, 503)
  })

  test('every reason that applies is listed, not just the first', () => {
    // A resolver that never refreshed is usually ALSO on baked data. Reporting
    // one reason would hide the other and send whoever reads it down one path.
    const r = report({ source: 'baked', lastRefreshAt: null, didCount: 0 })
    assert.deepEqual(
      [...r.reasons].sort(),
      ['no-dids-indexed', 'no-successful-refresh', 'trust-source-baked'],
    )
  })
})
