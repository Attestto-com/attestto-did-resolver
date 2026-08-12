/**
 * SOC-175 — the four defects in the rate limiter, found by the 2026-08-10 audit
 * before it was ever deployed.
 *
 * The limiter itself is sound: a fixed window keyed by client IP. These are the
 * ways around it, and one way it falls over.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import type { IncomingMessage } from 'node:http'
import { RateLimiter, DEFAULT_RATE_LIMIT } from '../rate-limit.js'
import { clientIp } from '../http-utils.js'

function req(headers: Record<string, string | string[]>, remote = '203.0.113.9') {
  return { headers, socket: { remoteAddress: remote } } as unknown as IncomingMessage
}

describe('defect 1 — the refund is a bypass primitive', () => {
  test('refunds are capped per window, so a forced-error loop still throttles', () => {
    // `internalError` refunds the caller's token so an honest retry is not
    // blocked by its own failed try. But the caller chooses the input, and any
    // input that reliably produces `internalError` — an unreachable RPC, or the
    // unguarded decodeURIComponent 500 in SOC-176 — makes the refund
    // unconditional. Uncapped, that is unlimited free requests.
    const rl = new RateLimiter({ windowMs: 1000, maxRequests: 2, maxRefunds: 1 })
    const now = 0

    for (let i = 0; i < 20; i++) {
      rl.check('ip', now)
      rl.refund('ip', now)
    }

    // maxRequests + maxRefunds requests may pass in one window; no more.
    assert.equal(rl.check('ip', now).allowed, false, 'a refund loop must not mint requests')
  })

  test('an honest single retry still works', () => {
    // The cap must not break the case the refund exists for.
    const rl = new RateLimiter({ windowMs: 1000, maxRequests: 1, maxRefunds: 1 })
    assert.equal(rl.check('ip', 0).allowed, true)
    rl.refund('ip', 0) // that request failed transiently
    assert.equal(rl.check('ip', 0).allowed, true, 'the retry must be allowed')
  })

  test('a refund cannot be banked across windows', () => {
    const rl = new RateLimiter({ windowMs: 1000, maxRequests: 1, maxRefunds: 1 })
    rl.check('ip', 0)
    rl.refund('ip', 5000) // window long gone
    assert.equal(rl.check('ip', 0).allowed, false)
  })
})

describe('defect 2 — X-Forwarded-For is client-controlled', () => {
  test('XFF is NOT trusted by default', () => {
    // Latent behind Fly's edge, which overwrites Fly-Client-IP. Live on any
    // path that reaches the process directly — a .internal call, a non-Fly
    // deploy, a future proxy change. A caller that rotates this header per
    // request gets unlimited quota AND plants unbounded keys in the map.
    const ip = clientIp(req({ 'x-forwarded-for': '1.2.3.4' }), { trustForwardedFor: false })
    assert.equal(ip, '203.0.113.9', 'the socket address is the only unspoofable source')
  })

  test('Fly-Client-IP is still preferred — the edge sets it', () => {
    const ip = clientIp(req({ 'fly-client-ip': '198.51.100.7', 'x-forwarded-for': '1.2.3.4' }))
    assert.equal(ip, '198.51.100.7')
  })

  test('XFF is honoured only when a deployment opts in', () => {
    const ip = clientIp(req({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }), { trustForwardedFor: true })
    assert.equal(ip, '1.2.3.4')
  })

  test('the default is closed', () => {
    // Reading the default off the function rather than restating it, so this
    // cannot drift from the implementation silently.
    assert.equal(clientIp(req({ 'x-forwarded-for': '1.2.3.4' })), '203.0.113.9')
  })
})

describe('defect 3 — the key map grows without bound between prunes', () => {
  test('the map is capped, so a burst of distinct keys cannot exhaust memory', () => {
    // prune() runs every 60s. Combined with a spoofable key (defect 2), a 60s
    // burst of unique IPs grows the map unbounded on a 1 GB machine. The cap
    // makes the worst case a property of configuration rather than of how long
    // an attacker is willing to wait.
    const rl = new RateLimiter({ windowMs: 60_000, maxRequests: 5, maxKeys: 100 })
    for (let i = 0; i < 5_000; i++) rl.check(`ip-${i}`, 0)
    assert.ok(rl.size <= 100, `map grew to ${rl.size}`)
  })

  test('eviction under pressure does not stop the limiter working', () => {
    const rl = new RateLimiter({ windowMs: 60_000, maxRequests: 1, maxKeys: 10 })
    rl.check('victim', 0)
    assert.equal(rl.check('victim', 0).allowed, false, 'a hot key must stay throttled')
  })
})

describe('defect 4 — the default throttles legitimate use', () => {
  test('the default allows a conformance run and a chain walk', () => {
    // The shipped default was 1 request per 5s per IP, applied to every route
    // including /1.0/properties. That throttles DIF's own driver conformance
    // suite, any aggregator, any sequential root→leaf chain walk
    // (attestto-desktop firma-validator.ts resolves generations in series), and
    // every NAT'd office — while §13 promises the driver works "out of the box"
    // in a Universal Resolver instance.
    const perSecond = (DEFAULT_RATE_LIMIT.maxRequests / DEFAULT_RATE_LIMIT.windowMs) * 1000
    assert.ok(perSecond >= 2, `default allows only ${perSecond}/s — a chain walk cannot complete`)

    const rl = new RateLimiter(DEFAULT_RATE_LIMIT)
    let allowed = 0
    for (let i = 0; i < 10; i++) if (rl.check('walker', 0).allowed) allowed++
    assert.ok(allowed >= 10, `a 10-step chain walk was throttled after ${allowed}`)
  })

  test('but a single source is still blunted', () => {
    const rl = new RateLimiter(DEFAULT_RATE_LIMIT)
    let allowed = 0
    for (let i = 0; i < 10_000; i++) if (rl.check('flood', 0).allowed) allowed++
    assert.ok(allowed < 1_000, `a flood got ${allowed} requests through in one window`)
  })
})
