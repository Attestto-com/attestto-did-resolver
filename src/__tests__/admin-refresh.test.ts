import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkBearer } from '../admin-auth.js'

test('checkBearer: 503 when secret is not configured', () => {
  assert.deepEqual(checkBearer('Bearer whatever', undefined), { ok: false, status: 503 })
  assert.deepEqual(checkBearer('Bearer whatever', ''), { ok: false, status: 503 })
})

test('checkBearer: 401 on missing or wrong token', () => {
  assert.deepEqual(checkBearer(undefined, 'sekret'), { ok: false, status: 401 })
  assert.deepEqual(checkBearer('Bearer nope', 'sekret'), { ok: false, status: 401 })
  assert.deepEqual(checkBearer('sekret', 'sekret'), { ok: false, status: 401 }) // missing "Bearer "
})

test('checkBearer: ok on exact match', () => {
  assert.deepEqual(checkBearer('Bearer sekret', 'sekret'), { ok: true, status: 200 })
})
