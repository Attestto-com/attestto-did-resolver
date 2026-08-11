/**
 * The health verdict, derived from trust state rather than asserted.
 *
 * `/health` used to return a hardcoded `status: 'ok'`. It printed `source` and
 * `lastRefreshAt` in the body — so the facts were there — but nothing turned
 * them into a verdict, and the live instance has been reporting green while
 * serving `source: "baked"` with `lastRefreshAt: null`: the published trust
 * data never loaded and the resolver answers from whatever the image contained.
 *
 * A control that cannot fail is not a control. This module exists so there is
 * an input for which the answer is NOT ok, and so a test can name it.
 */

export interface TrustMeta {
  /** Where the current trust store came from: 'baked' means the image's copy. */
  source: string
  version: string
  didCount: number
  lastRefreshAt: string | null
}

export type HealthReason =
  /** The published trust store never loaded; serving the image's baked copy. */
  | 'trust-source-baked'
  /** No refresh has ever succeeded. */
  | 'no-successful-refresh'
  /** The last successful refresh is older than two intervals — the timer has stopped. */
  | 'refresh-stale'
  /** Zero DIDs indexed: every did:pki query answers notFound. */
  | 'no-dids-indexed'

export interface HealthReport {
  status: 'ok' | 'degraded'
  httpStatus: 200 | 503
  reasons: HealthReason[]
}

/**
 * @param refreshIntervalMs the configured refresh cadence; staleness is judged
 *   at TWICE this, so a single missed run — an npm blip — is not an alert.
 *   A threshold that trips on the normal cadence is a threshold that gets muted.
 */
export function healthReport(
  meta: TrustMeta,
  now: number,
  refreshIntervalMs: number,
): HealthReport {
  const reasons: HealthReason[] = []

  if (meta.source === 'baked') reasons.push('trust-source-baked')
  if (meta.didCount <= 0) reasons.push('no-dids-indexed')

  if (meta.lastRefreshAt === null) {
    reasons.push('no-successful-refresh')
  } else {
    const at = Date.parse(meta.lastRefreshAt)
    // `Number.isNaN` first, explicitly: every comparison against NaN is false,
    // so `now - NaN > threshold` would report FRESH for an unparseable value.
    // That is how a staleness check silently passes on garbage.
    if (Number.isNaN(at) || now - at > 2 * refreshIntervalMs) reasons.push('refresh-stale')
  }

  return {
    status: reasons.length === 0 ? 'ok' : 'degraded',
    httpStatus: reasons.length === 0 ? 200 : 503,
    reasons,
  }
}
