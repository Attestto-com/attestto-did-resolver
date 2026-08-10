import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { IncomingMessage } from 'node:http'
import { readBodyCapped, clientIp } from '../http-utils.js'

function fakeReq(headers: Record<string, string | string[]>, remoteAddress?: string): IncomingMessage {
  return { headers, socket: { remoteAddress } } as unknown as IncomingMessage
}

function fakeIterable(...chunks: string[]): AsyncIterable<Buffer | string> {
  return {
    [Symbol.asyncIterator]: async function* () {
      for (const c of chunks) yield Buffer.from(c)
    },
  }
}

test('readBodyCapped returns concatenated buffer when under limit', async () => {
  const result = await readBodyCapped(fakeIterable('hello', ' ', 'world'), 4096)
  assert.equal(result.toString(), 'hello world')
})

test('readBodyCapped returns empty buffer for empty body', async () => {
  const result = await readBodyCapped(fakeIterable(), 4096)
  assert.equal(result.length, 0)
})

test('readBodyCapped throws RangeError when body exceeds limit', async () => {
  const big = 'x'.repeat(100)
  await assert.rejects(
    () => readBodyCapped(fakeIterable(big, big), 150),
    RangeError,
  )
})

test('readBodyCapped throws RangeError exactly at limit boundary', async () => {
  // 4096 bytes exactly → ok; 4097 → throws
  const exactly = 'a'.repeat(4096)
  const result = await readBodyCapped(fakeIterable(exactly), 4096)
  assert.equal(result.length, 4096)

  await assert.rejects(
    () => readBodyCapped(fakeIterable(exactly + 'a'), 4096),
    RangeError,
  )
})

test('clientIp prefers the Fly-Client-IP header', () => {
  const req = fakeReq({ 'fly-client-ip': '203.0.113.7', 'x-forwarded-for': '10.0.0.1' }, '172.16.0.1')
  assert.equal(clientIp(req), '203.0.113.7')
})

test('clientIp falls back to the first X-Forwarded-For hop', () => {
  const req = fakeReq({ 'x-forwarded-for': '203.0.113.9, 10.0.0.1, 10.0.0.2' }, '172.16.0.1')
  assert.equal(clientIp(req), '203.0.113.9')
})

test('clientIp falls back to the socket address', () => {
  const req = fakeReq({}, '172.16.0.5')
  assert.equal(clientIp(req), '172.16.0.5')
})

test('clientIp returns "unknown" when nothing is available', () => {
  const req = fakeReq({}, undefined)
  assert.equal(clientIp(req), 'unknown')
})

