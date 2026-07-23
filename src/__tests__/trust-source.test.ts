import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { extractTarball, fetchNpm, fetchGitHubMain } from '../trust-source.js'

const FIX = join(fileURLToPath(new URL('.', import.meta.url)), 'fixtures')

test('extractTarball pulls only countries/ and strips the top dir', async () => {
  const tgz = readFileSync(join(FIX, 'npm-trust.tgz'))
  const { countriesDir, tempDir } = await extractTarball(tgz)
  try {
    assert.ok(existsSync(join(countriesDir, 'de', 'current', 'manifest.json')))
    assert.ok(existsSync(join(countriesDir, 'cr', 'current', 'manifest.json')))
    assert.equal(countriesDir, join(tempDir, 'countries'))
  } finally {
    rmSync(tempDir, { recursive: true, force: true })
  }
})

test('fetchNpm resolves version + tarball via injected fetch', async () => {
  const tgz = readFileSync(join(FIX, 'npm-trust.tgz'))
  const fetchImpl = (async (url: string) => {
    if (url.includes('registry.npmjs.org')) {
      return new Response(JSON.stringify({
        'dist-tags': { latest: '1.2.3' },
        versions: { '1.2.3': { dist: { tarball: 'https://example.test/pkg.tgz' } } },
      }))
    }
    return new Response(tgz)
  }) as unknown as typeof fetch
  const ft = await fetchNpm({ fetchImpl })
  try {
    assert.equal(ft.source, 'npm')
    assert.equal(ft.version, '1.2.3')
    assert.ok(existsSync(join(ft.countriesDir, 'de', 'current', 'manifest.json')))
  } finally {
    rmSync(ft.tempDir, { recursive: true, force: true })
  }
})

test('fetchGitHubMain extracts the main tarball via injected fetch', async () => {
  const tgz = readFileSync(join(FIX, 'github-trust.tar.gz'))
  const fetchImpl = (async () => new Response(tgz)) as unknown as typeof fetch
  const ft = await fetchGitHubMain({ fetchImpl })
  try {
    assert.equal(ft.source, 'main')
    assert.equal(ft.version, 'main')
    assert.ok(existsSync(join(ft.countriesDir, 'fr', 'current', 'manifest.json')))
  } finally {
    rmSync(ft.tempDir, { recursive: true, force: true })
  }
})

// I-1: malformed tarball must reject AND must not leak the temp dir
test('extractTarball cleans up temp dir on extraction failure', async () => {
  const before = readdirSync(tmpdir()).filter(e => e.startsWith('attestto-trust-')).length
  await assert.rejects(() => extractTarball(Buffer.from('not a tarball')))
  const after = readdirSync(tmpdir()).filter(e => e.startsWith('attestto-trust-')).length
  assert.equal(after, before, 'temp dir count must not increase on failure')
})

// I-2: fetchNpm and fetchGitHubMain must pass an AbortSignal to every fetch call
test('fetchNpm passes AbortSignal to both fetch calls', async () => {
  const tgz = readFileSync(join(FIX, 'npm-trust.tgz'))
  let metaGotSignal = false
  let tgzGotSignal = false
  const fetchImpl = (async (url: string, opts?: RequestInit) => {
    if (url.includes('registry.npmjs.org')) {
      metaGotSignal = opts?.signal instanceof AbortSignal
      return new Response(JSON.stringify({
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': { dist: { tarball: 'https://example.test/pkg.tgz' } } },
      }))
    }
    tgzGotSignal = opts?.signal instanceof AbortSignal
    return new Response(tgz)
  }) as unknown as typeof fetch
  const ft = await fetchNpm({ fetchImpl })
  rmSync(ft.tempDir, { recursive: true, force: true })
  assert.ok(metaGotSignal, 'metadata fetch must receive an AbortSignal')
  assert.ok(tgzGotSignal, 'tarball fetch must receive an AbortSignal')
})

test('fetchGitHubMain passes AbortSignal to fetch', async () => {
  const tgz = readFileSync(join(FIX, 'github-trust.tar.gz'))
  let gotSignal = false
  const fetchImpl = (async (_url: string, opts?: RequestInit) => {
    gotSignal = opts?.signal instanceof AbortSignal
    return new Response(tgz)
  }) as unknown as typeof fetch
  const ft = await fetchGitHubMain({ fetchImpl })
  rmSync(ft.tempDir, { recursive: true, force: true })
  assert.ok(gotSignal, 'fetch must receive an AbortSignal')
})
