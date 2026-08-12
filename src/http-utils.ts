import type { IncomingMessage } from 'node:http'

/**
 * Read a request body up to `limit` bytes. Throws a RangeError if the limit is exceeded.
 * The limit guards against memory-DoS on auth-gated endpoints.
 */
export async function readBodyCapped(req: AsyncIterable<Buffer | string>, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const c of req) {
    const chunk = Buffer.isBuffer(c) ? c : Buffer.from(c as string)
    total += chunk.byteLength
    if (total > limit) {
      throw new RangeError(`Request body exceeds ${limit} byte limit`)
    }
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

/**
 * Client IP for rate limiting.
 *
 * `Fly-Client-IP` is set by Fly's edge and overwritten on every request, so a
 * client cannot forge it — it is preferred and trusted.
 *
 * `X-Forwarded-For` is NOT trusted by default. It is an ordinary request header
 * under the caller's control, so honouring it hands the caller their own rate
 * limit key: rotate the header per request for unlimited quota, and plant an
 * unbounded number of keys in the limiter's map on the way. That is latent
 * behind Fly's edge and live on any path that reaches the process directly — a
 * `.internal` call, a non-Fly deploy, a future proxy change. A deployment that
 * genuinely sits behind a trusted proxy opts in explicitly.
 *
 * Falling back to the socket address means a missing IP degrades to one shared
 * bucket rather than throwing.
 */
export interface ClientIpOptions {
  /**
   * Honour `X-Forwarded-For`. Only enable when a trusted proxy in front of this
   * process is known to overwrite it — otherwise it is caller-controlled.
   */
  trustForwardedFor?: boolean
}

export function clientIp(req: IncomingMessage, opts: ClientIpOptions = {}): string {
  const flyIp = req.headers['fly-client-ip']
  if (typeof flyIp === 'string' && flyIp.length) return flyIp.trim()

  if (opts.trustForwardedFor) {
    const xff = req.headers['x-forwarded-for']
    const xffValue = Array.isArray(xff) ? xff[0] : xff
    if (xffValue) {
      const first = xffValue.split(',')[0]?.trim()
      if (first) return first
    }
  }

  return req.socket?.remoteAddress ?? 'unknown'
}
