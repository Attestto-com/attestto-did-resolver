/**
 * In-memory per-key fixed-window rate limiter.
 *
 * The resolver runs as a single Node process per Fly machine and needs a cheap,
 * dependency-free throttle for its public, unauthenticated surface. A fixed
 * window keyed by client IP gives "N requests per window, per IP" without a
 * Redis dependency. State is per-machine — acceptable here because the goal is
 * to blunt single-source floods, not to enforce a global quota.
 */

export interface RateLimitConfig {
  /** Window length in milliseconds. */
  windowMs: number
  /** Max requests allowed per key within a window. */
  maxRequests: number
  /**
   * Max tokens `refund()` may return per key per window.
   *
   * The refund exists so an honest retry after a transient upstream failure is
   * not blocked by its own failed attempt. But the CALLER chooses the input,
   * and any input that reliably produces `internalError` makes the refund
   * unconditional — an unreachable RPC, or the unguarded `decodeURIComponent`
   * 500 in SOC-176. Uncapped, that is a bypass primitive: check, force an
   * error, get the token back, repeat forever.
   */
  maxRefunds?: number
  /**
   * Hard cap on tracked keys.
   *
   * `prune()` only runs periodically (every 60s in `server.ts`), so between
   * prunes the map grows with every distinct key. Combined with a spoofable
   * key, a burst of unique addresses is an unbounded allocation on a 1 GB
   * machine. The cap makes the worst case a function of configuration rather
   * than of how long an attacker is willing to wait.
   */
  maxKeys?: number
}

/**
 * The shipped default: 30 requests / 10s / IP.
 *
 * It was 1 request per 5 seconds, applied to every route including
 * `/1.0/properties`. That throttles DIF's own driver conformance suite, any
 * aggregator, any sequential root→leaf chain walk, and every NAT'd office —
 * while §13 promises the driver works "out of the box" in a Universal Resolver
 * instance. A throttle nobody can pass is an outage with extra steps.
 *
 * 3 req/s still blunts a single-source flood, which is what a per-machine
 * in-memory limiter is for.
 */
export const DEFAULT_RATE_LIMIT: Required<Pick<RateLimitConfig, 'windowMs' | 'maxRequests'>> = {
  windowMs: 10_000,
  maxRequests: 30,
}

export interface RateLimitResult {
  allowed: boolean
  /** Seconds until the current window resets. 0 when allowed. */
  retryAfterSec: number
  /** Requests still permitted in the current window. */
  remaining: number
}

export class RateLimiter {
  private readonly hits = new Map<string, { count: number; windowStart: number; refunds: number }>()

  constructor(private readonly config: RateLimitConfig) {}

  /**
   * Record a request for `key` and report whether it is allowed.
   * `now` is injectable for deterministic tests; defaults to wall-clock.
   */
  check(key: string, now: number = Date.now()): RateLimitResult {
    const { windowMs, maxRequests } = this.config
    let entry = this.hits.get(key)
    if (!entry || now - entry.windowStart >= windowMs) {
      entry = { count: 0, windowStart: now, refunds: 0 }
      this.evictIfFull(now)
      this.hits.set(key, entry)
    }

    if (entry.count >= maxRequests) {
      const retryAfterSec = Math.max(1, Math.ceil((entry.windowStart + windowMs - now) / 1000))
      return { allowed: false, retryAfterSec, remaining: 0 }
    }

    entry.count++
    return { allowed: true, retryAfterSec: 0, remaining: maxRequests - entry.count }
  }

  /**
   * Give back a previously consumed request for `key` in the current window.
   * Used when a request turned out to be a transient error we invite the caller
   * to retry immediately — the retry must not be blocked by its own failed try.
   * No-op if the window has since rolled over or the count is already zero.
   */
  refund(key: string, now: number = Date.now()): void {
    const entry = this.hits.get(key)
    if (!entry) return
    if (now - entry.windowStart >= this.config.windowMs) return // window rolled over
    if (entry.count <= 0) return
    // 🔒 The cap is what stops check→force-error→refund from minting requests.
    if (entry.refunds >= (this.config.maxRefunds ?? 1)) return
    entry.refunds++
    entry.count--
  }

  /** Drop expired windows so the map does not grow without bound. Call periodically. */
  prune(now: number = Date.now()): void {
    for (const [key, entry] of this.hits) {
      if (now - entry.windowStart >= this.config.windowMs) this.hits.delete(key)
    }
  }

  /**
   * Make room before inserting a new key. Drops expired windows first; if the
   * map is still at the cap, evicts the oldest window — the least likely to be
   * an active client, and in the flood case the attacker's own earliest key.
   */
  private evictIfFull(now: number): void {
    const cap = this.config.maxKeys ?? 100_000
    if (this.hits.size < cap) return

    this.prune(now)
    while (this.hits.size >= cap) {
      // Map iteration is insertion-ordered, so the first entry is the oldest
      // window still tracked.
      const oldest = this.hits.keys().next()
      if (oldest.done) return
      this.hits.delete(oldest.value)
    }
  }

  /** Number of tracked keys — used by tests and diagnostics. */
  get size(): number {
    return this.hits.size
  }
}
