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
}

export interface RateLimitResult {
  allowed: boolean
  /** Seconds until the current window resets. 0 when allowed. */
  retryAfterSec: number
  /** Requests still permitted in the current window. */
  remaining: number
}

export class RateLimiter {
  private readonly hits = new Map<string, { count: number; windowStart: number }>()

  constructor(private readonly config: RateLimitConfig) {}

  /**
   * Record a request for `key` and report whether it is allowed.
   * `now` is injectable for deterministic tests; defaults to wall-clock.
   */
  check(key: string, now: number = Date.now()): RateLimitResult {
    const { windowMs, maxRequests } = this.config
    let entry = this.hits.get(key)
    if (!entry || now - entry.windowStart >= windowMs) {
      entry = { count: 0, windowStart: now }
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
    if (entry && now - entry.windowStart < this.config.windowMs && entry.count > 0) {
      entry.count--
    }
  }

  /** Drop expired windows so the map does not grow without bound. Call periodically. */
  prune(now: number = Date.now()): void {
    for (const [key, entry] of this.hits) {
      if (now - entry.windowStart >= this.config.windowMs) this.hits.delete(key)
    }
  }

  /** Number of tracked keys — used by tests and diagnostics. */
  get size(): number {
    return this.hits.size
  }
}
