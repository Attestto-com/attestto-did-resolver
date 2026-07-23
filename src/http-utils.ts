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
