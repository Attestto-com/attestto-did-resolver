import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, cpSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TrustRegistry } from '../registry.js'
import { DidPkiResolver } from '../pki-resolver.js'
import { CrlRevocationService } from '../crl-revocation.js'
import { RefreshManager, type TrustState } from '../trust-refresh.js'
import type { FetchedTrust } from '../trust-source.js'

// Build a countries/ dir on disk with N single-cert countries, each 1 DID.
function makeCountriesDir(ccs: string[]): string {
  const root = mkdtempSync(join(tmpdir(), 'ref-fix-'))
  const countries = join(root, 'countries')
  for (const cc of ccs) {
    const cur = join(countries, cc, 'current')
    mkdirSync(cur, { recursive: true })
    writeFileSync(join(cur, 'manifest.json'), JSON.stringify({
      country: cc,
      certificates: [{ file: 'root.pem', sha256: 'x', subject: `Root ${cc}`, organization: `Org ${cc}`, commonName: `Root ${cc}`, role: 'root' }],
    }))
    writeFileSync(join(cur, 'root.pem'), '-----BEGIN CERTIFICATE-----\nMIIBTEST\n-----END CERTIFICATE-----\n')
  }
  return countries
}

function stateFrom(countriesDir: string): TrustState {
  const registry = new TrustRegistry(countriesDir)
  registry.load()
  const pkiResolver = new DidPkiResolver(registry)
  return {
    registry, pkiResolver,
    crl: new CrlRevocationService(countriesDir),
    meta: { source: 'baked', version: 'baked', didCount: pkiResolver.listDids().length, lastRefreshAt: null },
    tempDir: null,
  }
}

// A fetcher that copies a source countries dir into a fresh temp (so cleanup is safe).
function fetcherFrom(sourceCountriesDir: string, version: string, source: 'npm' | 'main') {
  return async (): Promise<FetchedTrust> => {
    const tempDir = mkdtempSync(join(tmpdir(), 'ref-fetch-'))
    cpSync(sourceCountriesDir, join(tempDir, 'countries'), { recursive: true })
    return { countriesDir: join(tempDir, 'countries'), tempDir, version, source }
  }
}

test('refresh swaps registry and updates meta on a healthy fetch', async () => {
  const baked = makeCountriesDir(['de', 'cr'])
  const state = stateFrom(baked)
  const before = state.meta.didCount
  const fresh = makeCountriesDir(['de', 'cr', 'fr'])
  const mgr = new RefreshManager(state, { fetchTrust: fetcherFrom(fresh, '9.9.9', 'npm'), debounceMs: 0 })
  const r = await mgr.refresh('npm', 'test')
  assert.equal(r.ok, true)
  assert.ok(state.meta.didCount > before, 'DID count should grow')
  assert.equal(state.meta.version, '9.9.9')
  assert.equal(state.meta.source, 'npm')
  assert.equal(state.tempDir !== null, true)
})

test('refresh rejects a collapsed dataset below the sanity floor', async () => {
  const baked = makeCountriesDir(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'])
  const state = stateFrom(baked)
  const before = state.meta.didCount
  const collapsed = makeCountriesDir(['a']) // 1 DID vs 10 → below 0.9 floor
  const mgr = new RefreshManager(state, { fetchTrust: fetcherFrom(collapsed, '9.9.9', 'npm'), debounceMs: 0 })
  const r = await mgr.refresh('npm', 'test')
  assert.equal(r.ok, false)
  assert.match(r.reason, /floor/)
  assert.equal(state.meta.didCount, before, 'live data unchanged')
})

test('refresh keeps old data when the fetch throws', async () => {
  const baked = makeCountriesDir(['de', 'cr'])
  const state = stateFrom(baked)
  const before = state.meta.didCount
  const mgr = new RefreshManager(state, { fetchTrust: async () => { throw new Error('network down') }, debounceMs: 0 })
  const r = await mgr.refresh('npm', 'test')
  assert.equal(r.ok, false)
  assert.equal(state.meta.didCount, before)
})

test('refresh debounces a second call inside the window', async () => {
  const baked = makeCountriesDir(['de', 'cr'])
  const state = stateFrom(baked)
  const fresh = makeCountriesDir(['de', 'cr', 'fr'])
  let now = 1000
  const mgr = new RefreshManager(state, {
    fetchTrust: fetcherFrom(fresh, '1', 'npm'),
    debounceMs: 30000,
    now: () => now,
  })
  const first = await mgr.refresh('npm', 'test')
  assert.equal(first.ok, true)
  now = 1000 + 5000 // 5s later, inside 30s window
  const second = await mgr.refresh('npm', 'test')
  assert.equal(second.ok, false)
  assert.match(second.reason, /debounc/)
})

// M-1: main refresh is NOT blocked by debounce, but npm IS
test('main refresh bypasses debounce window after an npm refresh', async () => {
  const baked = makeCountriesDir(['de', 'cr'])
  const state = stateFrom(baked)
  const fresh = makeCountriesDir(['de', 'cr', 'fr'])
  let now = 1000
  const mgr = new RefreshManager(state, {
    fetchTrust: fetcherFrom(fresh, '2', 'main'),
    debounceMs: 30000,
    now: () => now,
  })
  // First refresh (npm) sets lastAttemptAt
  const first = await mgr.refresh('npm', 'scheduled')
  assert.equal(first.ok, true)
  now = 1000 + 5000 // 5s later, inside debounce window
  // main refresh must NOT be debounced
  const webhook = await mgr.refresh('main', 'webhook')
  assert.equal(webhook.ok, true, 'main refresh inside debounce window must succeed')
})

test('npm refresh within debounce window after npm refresh is still debounced', async () => {
  const baked = makeCountriesDir(['de', 'cr'])
  const state = stateFrom(baked)
  const fresh = makeCountriesDir(['de', 'cr', 'fr'])
  let now = 1000
  const mgr = new RefreshManager(state, {
    fetchTrust: fetcherFrom(fresh, '3', 'npm'),
    debounceMs: 30000,
    now: () => now,
  })
  const first = await mgr.refresh('npm', 'scheduled')
  assert.equal(first.ok, true)
  now = 1000 + 5000 // 5s later, inside debounce window
  const second = await mgr.refresh('npm', 'scheduled')
  assert.equal(second.ok, false, 'npm refresh inside debounce window must be debounced')
  assert.match(second.reason, /debounc/)
})
