import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readBodyCapped } from '../http-utils.js'

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
