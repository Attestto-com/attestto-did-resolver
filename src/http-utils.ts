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
 * Best-effort client IP for rate limiting behind Fly.io's proxy.
 *
 * Fly sets `Fly-Client-IP` to the real remote address, so it is preferred and
 * cannot be spoofed by the client (the edge overwrites it). We fall back to the
 * first `X-Forwarded-For` hop, then the raw socket address, then "unknown" so a
 * missing IP degrades to a single shared bucket rather than throwing.
 */
export function clientIp(req: IncomingMessage): string {
  const flyIp = req.headers['fly-client-ip']
  if (typeof flyIp === 'string' && flyIp.length) return flyIp.trim()

  const xff = req.headers['x-forwarded-for']
  const xffValue = Array.isArray(xff) ? xff[0] : xff
  if (xffValue) {
    const first = xffValue.split(',')[0]?.trim()
    if (first) return first
  }

  return req.socket?.remoteAddress ?? 'unknown'
}
