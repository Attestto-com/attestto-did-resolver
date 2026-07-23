import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync, rmSync } from 'node:fs'
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
