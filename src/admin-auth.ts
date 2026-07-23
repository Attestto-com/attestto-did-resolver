/** Constant-time bearer-token check for the admin refresh endpoint. */
import { timingSafeEqual } from 'node:crypto'

export function checkBearer(
  authHeader: string | undefined,
  secret: string | undefined,
): { ok: boolean; status: number } {
  if (!secret) return { ok: false, status: 503 } // endpoint disabled
  const prefix = 'Bearer '
  if (!authHeader || !authHeader.startsWith(prefix)) return { ok: false, status: 401 }
  const token = Buffer.from(authHeader.slice(prefix.length))
  const expected = Buffer.from(secret)
  if (token.length !== expected.length) return { ok: false, status: 401 }
  return timingSafeEqual(token, expected) ? { ok: true, status: 200 } : { ok: false, status: 401 }
}
