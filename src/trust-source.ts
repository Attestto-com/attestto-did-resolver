/**
 * Trust source — fetch + extract the countries/ tree from a remote tarball.
 *
 * Two sources share one extractor:
 *   - fetchNpm():        latest @attestto/trust tarball from the npm registry (default)
 *   - fetchGitHubMain(): the attestto-trust main branch tarball from GitHub codeload
 *
 * Both tarballs wrap the tree in a single top-level directory ("package/" for npm,
 * "<repo>-main/" for GitHub); extractTarball strips it and keeps only countries/.
 */
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as tar from 'tar'

const FETCH_TIMEOUT_MS = Number(process.env.REFRESH_FETCH_TIMEOUT_MS || 30_000)

export interface FetchedTrust {
  /** Absolute path to the extracted countries/ directory. */
  countriesDir: string
  /** Absolute path to the temp root to remove once the data is no longer live. */
  tempDir: string
  /** npm semver, or "main" for the GitHub source. */
  version: string
  source: 'npm' | 'main'
}

/** Extract every entry whose second path component is "countries" into a fresh temp dir. */
export async function extractTarball(tgz: Buffer): Promise<{ countriesDir: string; tempDir: string }> {
  const tempDir = mkdtempSync(join(tmpdir(), 'attestto-trust-'))
  const tgzPath = join(tempDir, 'src.tgz')
  writeFileSync(tgzPath, tgz)
  try {
    await tar.x({
      file: tgzPath,
      cwd: tempDir,
      strip: 1, // drop the single top-level wrapper dir
      filter: (path: string) => path.split('/')[1] === 'countries',
    })
  } catch (e) {
    rmSync(tempDir, { recursive: true, force: true })
    throw e
  } finally {
    rmSync(tgzPath, { force: true })
  }
  return { countriesDir: join(tempDir, 'countries'), tempDir }
}

async function fetchBuffer(url: string, fetchImpl: typeof fetch): Promise<Buffer> {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
  if (!res.ok) throw new Error(`fetch ${url} → HTTP ${res.status}`)
  return Buffer.from(await res.arrayBuffer())
}

export async function fetchNpm(opts: { pkg?: string; fetchImpl?: typeof fetch } = {}): Promise<FetchedTrust> {
  const pkg = opts.pkg ?? '@attestto/trust'
  const fetchImpl = opts.fetchImpl ?? fetch
  const metaUrl = `https://registry.npmjs.org/${pkg.replace('/', '%2F')}`
  const metaRes = await fetchImpl(metaUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
  if (!metaRes.ok) throw new Error(`npm registry ${metaUrl} → HTTP ${metaRes.status}`)
  const meta = (await metaRes.json()) as {
    'dist-tags'?: { latest?: string }
    versions?: Record<string, { dist?: { tarball?: string } }>
  }
  const version = meta['dist-tags']?.latest
  const tarball = version ? meta.versions?.[version]?.dist?.tarball : undefined
  if (!version || !tarball) throw new Error(`npm registry response missing latest tarball for ${pkg}`)
  const tgz = await fetchBuffer(tarball, fetchImpl)
  const { countriesDir, tempDir } = await extractTarball(tgz)
  return { countriesDir, tempDir, version, source: 'npm' }
}

export async function fetchGitHubMain(opts: { repo?: string; fetchImpl?: typeof fetch } = {}): Promise<FetchedTrust> {
  const repo = opts.repo ?? 'Attestto-com/attestto-trust'
  const fetchImpl = opts.fetchImpl ?? fetch
  const url = `https://codeload.github.com/${repo}/tar.gz/refs/heads/main`
  const tgz = await fetchBuffer(url, fetchImpl)
  const { countriesDir, tempDir } = await extractTarball(tgz)
  return { countriesDir, tempDir, version: 'main', source: 'main' }
}
