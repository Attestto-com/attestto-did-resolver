import { test } from 'node:test'
import assert from 'node:assert/strict'
import { RateLimiter } from '../rate-limit.js'

// 1 request per 5s window, per key — the resolver's public limit.
const cfg = { windowMs: 5000, maxRequests: 1 }

test('first request in a window is allowed', () => {
  const rl = new RateLimiter(cfg)
  const r = rl.check('1.2.3.4', 0)
  assert.equal(r.allowed, true)
  assert.equal(r.retryAfterSec, 0)
})

test('second request within the window is blocked with Retry-After', () => {
  const rl = new RateLimiter(cfg)
  rl.check('1.2.3.4', 0)
  const r = rl.check('1.2.3.4', 2000) // 2s later, still inside 5s window
  assert.equal(r.allowed, false)
  assert.equal(r.retryAfterSec, 3) // ceil((5000-2000)/1000)
})

test('retryAfterSec is at least 1 even at the window edge', () => {
  const rl = new RateLimiter(cfg)
  rl.check('1.2.3.4', 0)
  const r = rl.check('1.2.3.4', 4999)
  assert.equal(r.allowed, false)
  assert.equal(r.retryAfterSec, 1)
})

test('request after the window elapses is allowed again', () => {
  const rl = new RateLimiter(cfg)
  rl.check('1.2.3.4', 0)
  const r = rl.check('1.2.3.4', 5000) // window boundary — new window
  assert.equal(r.allowed, true)
})

test('different keys are limited independently', () => {
  const rl = new RateLimiter(cfg)
  assert.equal(rl.check('1.1.1.1', 0).allowed, true)
  assert.equal(rl.check('2.2.2.2', 0).allowed, true) // different IP, not blocked
  assert.equal(rl.check('1.1.1.1', 100).allowed, false)
})

test('prune drops expired windows to bound memory', () => {
  const rl = new RateLimiter(cfg)
  rl.check('1.1.1.1', 0)
  rl.check('2.2.2.2', 0)
  assert.equal(rl.size, 2)
  rl.prune(5000) // both windows expired
  assert.equal(rl.size, 0)
})

test('prune keeps still-active windows', () => {
  const rl = new RateLimiter(cfg)
  rl.check('1.1.1.1', 0)
  rl.check('2.2.2.2', 4000)
  rl.prune(5000) // only the first window has expired
  assert.equal(rl.size, 1)
})

test('refund returns the token so an immediate retry is allowed', () => {
  const rl = new RateLimiter(cfg)
  assert.equal(rl.check('1.2.3.4', 0).allowed, true) // consumes the 1/5s budget
  rl.refund('1.2.3.4', 0) // transient error → give it back
  assert.equal(rl.check('1.2.3.4', 0).allowed, true) // retry not blocked
})

test('refund never drops the count below zero', () => {
  const rl = new RateLimiter(cfg)
  rl.refund('nobody', 0) // no prior hit — must be a no-op, not go negative
  assert.equal(rl.check('nobody', 0).allowed, true)
  assert.equal(rl.check('nobody', 0).allowed, false) // exactly one allowed
})

test('refund is a no-op once the window has expired', () => {
  const rl = new RateLimiter(cfg)
  rl.check('1.2.3.4', 0)
  rl.refund('1.2.3.4', 6000) // window already rolled over; nothing to refund
  // fresh window at 6000 still grants the normal single request
  assert.equal(rl.check('1.2.3.4', 6000).allowed, true)
  assert.equal(rl.check('1.2.3.4', 6000).allowed, false)
})

test('supports a higher maxRequests config', () => {
  const rl = new RateLimiter({ windowMs: 1000, maxRequests: 3 })
  assert.equal(rl.check('x', 0).allowed, true)
  assert.equal(rl.check('x', 0).allowed, true)
  assert.equal(rl.check('x', 0).allowed, true)
  assert.equal(rl.check('x', 0).allowed, false)
})
