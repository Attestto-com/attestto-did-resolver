# Resolver Trust-Store Auto-Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the resolver pull fresh trust data on startup, on a timer, and on a merge-triggered webhook, so cert changes reach production without a manual `fly deploy`.

**Architecture:** A `trust-source` module fetches + extracts the `countries/` tree from an npm tarball (default) or GitHub `main` (webhook override). A `RefreshManager` builds a new registry from the fetched dir, validates a sanity floor, and atomically swaps live references in a mutable `TrustState` holder. `server.ts` reads that holder per-request, cold-starts from the baked snapshot, and exposes an authenticated `POST /admin/refresh`.

**Tech Stack:** Node ≥ 22, TypeScript (ESM, NodeNext), `node:test` + `tsx`, `node:http`, the `tar` package (new dependency), `@peculiar/x509` (already present via existing code).

## Global Constraints

- Repo: `/Users/eduardochongkan/Attestto/attestto-did-resolver`. All paths below are relative to it unless stated.
- ESM + NodeNext: every relative import ends in `.js` (e.g. `import { TrustRegistry } from './registry.js'`) even though the source file is `.ts`.
- Tests live in `src/__tests__/*.test.ts`; run with `npm test` (`node --import tsx --test src/**/*.test.ts`). No network in tests — use committed fixtures.
- Exactly ONE new runtime dependency: `tar`. Do not add others.
- Default source is the npm package `@attestto/trust`; GitHub `main` is used only when a caller requests `source: "main"`.
- Cold start still loads the baked snapshot at `TRUST_STORE_PATH`; a failed fetch must never leave the resolver empty or crash it.
- Sanity floor: a refresh is accepted only if the new DID count is ≥ `REFRESH_FLOOR_FRACTION` (default 0.9) × current DID count, and ≥ 1.
- The baked snapshot directory (`TRUST_STORE_PATH`) must NEVER be deleted by cleanup — only fetched temp dirs are removed.
- Commits: `git commit --no-gpg-sign`, no `Co-Authored-By` trailer, no Claude footer. `git add` explicit paths only, never `-A`.
- Attestto is spelled with double-t. Do not use the term "self-sovereign".
- Do not run `npm run dev` or start a long-running server; verify via `npm test` and one-shot node scripts only.

---

### Task 1: Trust source — fetch + extract (`src/trust-source.ts`)

**Files:**
- Modify: `package.json` (add `tar` dependency)
- Create: `src/trust-source.ts`
- Create: `src/__tests__/trust-source.test.ts`
- Create (fixtures, via a generator script): `src/__tests__/fixtures/npm-trust.tgz`, `src/__tests__/fixtures/github-trust.tar.gz`
- Create: `src/__tests__/fixtures/make-fixtures.sh` (reproducible fixture builder)

**Interfaces:**
- Produces:
  - `interface FetchedTrust { countriesDir: string; tempDir: string; version: string; source: 'npm' | 'main' }`
  - `function extractTarball(tgz: Buffer): Promise<{ countriesDir: string; tempDir: string }>` — extracts every archive entry whose second path component is `countries` into a fresh temp dir (stripping the first component), returns the temp root and the `countries/` path inside it.
  - `function fetchNpm(opts?: { pkg?: string; fetchImpl?: typeof fetch }): Promise<FetchedTrust>` — default `pkg = '@attestto/trust'`.
  - `function fetchGitHubMain(opts?: { repo?: string; fetchImpl?: typeof fetch }): Promise<FetchedTrust>` — default `repo = 'Attestto-com/attestto-trust'`.

- [ ] **Step 1: Add the `tar` dependency**

Edit `package.json` `dependencies` so it reads (keep `@solana/web3.js` as-is):

```json
  "dependencies": {
    "@solana/web3.js": "^1.98.0",
    "tar": "^7.4.3"
  },
```

Run: `npm install`
Expected: `tar` and its deps appear under `node_modules`, `package-lock.json` updated.

- [ ] **Step 2: Create the fixture generator and build fixtures**

Create `src/__tests__/fixtures/make-fixtures.sh`:

```bash
#!/usr/bin/env bash
# Reproducible test fixtures for trust-source.test.ts.
# Builds two tarballs whose layout mirrors (a) an npm @attestto/trust tarball
# (top dir "package/") and (b) a GitHub codeload tarball (top dir "attestto-trust-main/").
# Uses a tiny hand-built countries/ tree so the fixtures stay small and network-free.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Minimal country trees: two countries, each with current/manifest.json.
mk_country() {
  local root="$1" cc="$2" cn="$3"
  mkdir -p "$root/countries/$cc/current"
  cat > "$root/countries/$cc/current/manifest.json" <<JSON
{
  "country": "$cc",
  "certificates": [
    { "file": "root.pem", "sha256": "deadbeef", "subject": "$cn", "organization": "Test Org $cc", "commonName": "$cn" }
  ]
}
JSON
  cat > "$root/countries/$cc/current/root.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBFAKECERTFORTESTFIXTUREONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END CERTIFICATE-----
PEM
}

# npm-style tarball: top-level "package/"
npm_root="$work/package"
mk_country "$npm_root" "de" "Test Root DE"
mk_country "$npm_root" "cr" "Test Root CR"
tar -czf "$here/npm-trust.tgz" -C "$work" package

# github-style tarball: top-level "attestto-trust-main/"
gh_root="$work/attestto-trust-main"
mk_country "$gh_root" "de" "Test Root DE"
mk_country "$gh_root" "cr" "Test Root CR"
mk_country "$gh_root" "fr" "Test Root FR"
tar -czf "$here/github-trust.tar.gz" -C "$work" attestto-trust-main

echo "wrote npm-trust.tgz (de,cr) and github-trust.tar.gz (de,cr,fr)"
```

Run:
```bash
chmod +x src/__tests__/fixtures/make-fixtures.sh
src/__tests__/fixtures/make-fixtures.sh
```
Expected: prints `wrote npm-trust.tgz (de,cr) and github-trust.tar.gz (de,cr,fr)`, and both tarballs exist.

- [ ] **Step 3: Write the failing test**

Create `src/__tests__/trust-source.test.ts`:

```ts
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
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `npm test -- --test-name-pattern='extractTarball|fetchNpm|fetchGitHubMain'`
Expected: FAIL — `Cannot find module '../trust-source.js'`.

- [ ] **Step 5: Implement `src/trust-source.ts`**

```ts
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
  } finally {
    rmSync(tgzPath, { force: true })
  }
  return { countriesDir: join(tempDir, 'countries'), tempDir }
}

async function fetchBuffer(url: string, fetchImpl: typeof fetch): Promise<Buffer> {
  const res = await fetchImpl(url)
  if (!res.ok) throw new Error(`fetch ${url} → HTTP ${res.status}`)
  return Buffer.from(await res.arrayBuffer())
}

export async function fetchNpm(opts: { pkg?: string; fetchImpl?: typeof fetch } = {}): Promise<FetchedTrust> {
  const pkg = opts.pkg ?? '@attestto/trust'
  const fetchImpl = opts.fetchImpl ?? fetch
  const metaUrl = `https://registry.npmjs.org/${pkg.replace('/', '%2F')}`
  const metaRes = await fetchImpl(metaUrl)
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
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npm test -- --test-name-pattern='extractTarball|fetchNpm|fetchGitHubMain'`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json src/trust-source.ts src/__tests__/trust-source.test.ts src/__tests__/fixtures/make-fixtures.sh src/__tests__/fixtures/npm-trust.tgz src/__tests__/fixtures/github-trust.tar.gz
git commit --no-gpg-sign -m "feat(trust): add trust-source fetch+extract (npm + github main) — ATT-1063"
```

---

### Task 2: Refresh manager (`src/trust-refresh.ts`)

**Files:**
- Create: `src/trust-refresh.ts`
- Create: `src/__tests__/trust-refresh.test.ts`

**Interfaces:**
- Consumes: `FetchedTrust` from `./trust-source.js`; `TrustRegistry` from `./registry.js` (`constructor(path)`, `.load()`); `DidPkiResolver` from `./pki-resolver.js` (`constructor(registry)`, `.listDids(): string[]`); `CrlRevocationService` from `./crl-revocation.js` (`constructor(trustStorePath)`).
- Produces:
  - `interface TrustMeta { source: 'baked' | 'npm' | 'main'; version: string; didCount: number; lastRefreshAt: string | null }`
  - `interface TrustState { registry: TrustRegistry; pkiResolver: DidPkiResolver; crl: CrlRevocationService; meta: TrustMeta; tempDir: string | null }`
  - `interface RefreshResult { ok: boolean; source: 'npm' | 'main'; version?: string; didCount?: number; reason: string }`
  - `type TrustFetcher = (source: 'npm' | 'main') => Promise<FetchedTrust>`
  - `class RefreshManager { constructor(state: TrustState, opts?: { floorFraction?: number; debounceMs?: number; fetchTrust?: TrustFetcher; now?: () => number }); refresh(source: 'npm' | 'main', reason: string): Promise<RefreshResult> }`

- [ ] **Step 1: Write the failing test**

Create `src/__tests__/trust-refresh.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, cpSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
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
      certificates: [{ file: 'root.pem', sha256: 'x', subject: `Root ${cc}`, organization: `Org ${cc}`, commonName: `Root ${cc}` }],
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- --test-name-pattern='refresh '`
Expected: FAIL — `Cannot find module '../trust-refresh.js'`.

- [ ] **Step 3: Implement `src/trust-refresh.ts`**

```ts
/**
 * RefreshManager — rebuild the trust registry from a freshly fetched countries/ dir
 * and atomically swap it into a mutable TrustState, with a sanity floor, an in-flight
 * lock, and a debounce window. A failed refresh never mutates the live state.
 */
import { rmSync } from 'node:fs'
import { TrustRegistry } from './registry.js'
import { DidPkiResolver } from './pki-resolver.js'
import { CrlRevocationService } from './crl-revocation.js'
import { fetchNpm, fetchGitHubMain, type FetchedTrust } from './trust-source.js'

export interface TrustMeta {
  source: 'baked' | 'npm' | 'main'
  version: string
  didCount: number
  lastRefreshAt: string | null
}

export interface TrustState {
  registry: TrustRegistry
  pkiResolver: DidPkiResolver
  crl: CrlRevocationService
  meta: TrustMeta
  /** Temp dir backing the current data, or null when serving the baked snapshot. */
  tempDir: string | null
}

export interface RefreshResult {
  ok: boolean
  source: 'npm' | 'main'
  version?: string
  didCount?: number
  reason: string
}

export type TrustFetcher = (source: 'npm' | 'main') => Promise<FetchedTrust>

const defaultFetcher: TrustFetcher = (source) =>
  source === 'main' ? fetchGitHubMain() : fetchNpm()

export class RefreshManager {
  private state: TrustState
  private floorFraction: number
  private debounceMs: number
  private fetchTrust: TrustFetcher
  private now: () => number
  private inFlight: Promise<RefreshResult> | null = null
  private lastAttemptAt = 0

  constructor(state: TrustState, opts: {
    floorFraction?: number
    debounceMs?: number
    fetchTrust?: TrustFetcher
    now?: () => number
  } = {}) {
    this.state = state
    this.floorFraction = opts.floorFraction ?? 0.9
    this.debounceMs = opts.debounceMs ?? 30000
    this.fetchTrust = opts.fetchTrust ?? defaultFetcher
    this.now = opts.now ?? Date.now
  }

  refresh(source: 'npm' | 'main', reason: string): Promise<RefreshResult> {
    if (this.inFlight) return this.inFlight
    const since = this.now() - this.lastAttemptAt
    if (this.lastAttemptAt !== 0 && since < this.debounceMs) {
      return Promise.resolve({ ok: false, source, reason: `debounced (${since}ms < ${this.debounceMs}ms)` })
    }
    this.lastAttemptAt = this.now()
    this.inFlight = this.doRefresh(source, reason).finally(() => { this.inFlight = null })
    return this.inFlight
  }

  private async doRefresh(source: 'npm' | 'main', reason: string): Promise<RefreshResult> {
    let fetched: FetchedTrust | null = null
    try {
      fetched = await this.fetchTrust(source)
      const registry = new TrustRegistry(fetched.countriesDir)
      registry.load()
      const pkiResolver = new DidPkiResolver(registry)
      const didCount = pkiResolver.listDids().length
      const floor = Math.floor(this.floorFraction * this.state.meta.didCount)

      if (didCount < 1 || didCount < floor) {
        rmSync(fetched.tempDir, { recursive: true, force: true })
        return { ok: false, source, version: fetched.version, didCount,
          reason: `below floor (${didCount} < ${floor}) [${reason}]` }
      }

      const oldTempDir = this.state.tempDir
      this.state.registry = registry
      this.state.pkiResolver = pkiResolver
      this.state.crl = new CrlRevocationService(fetched.countriesDir)
      this.state.meta = { source, version: fetched.version, didCount,
        lastRefreshAt: new Date().toISOString() }
      this.state.tempDir = fetched.tempDir

      if (oldTempDir) rmSync(oldTempDir, { recursive: true, force: true })
      return { ok: true, source, version: fetched.version, didCount, reason }
    } catch (err) {
      if (fetched?.tempDir) rmSync(fetched.tempDir, { recursive: true, force: true })
      return { ok: false, source, reason: `error: ${err instanceof Error ? err.message : String(err)}` }
    }
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test -- --test-name-pattern='refresh '`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/trust-refresh.ts src/__tests__/trust-refresh.test.ts
git commit --no-gpg-sign -m "feat(trust): add RefreshManager (floor + atomic swap + debounce) — ATT-1063"
```

---

### Task 3: Server holder refactor + startup/scheduled refresh + health status (`src/server.ts`)

**Files:**
- Modify: `src/server.ts`

**Interfaces:**
- Consumes: `TrustState`, `RefreshManager` from `./trust-refresh.js`.
- Produces: a module-level `state: TrustState` and `refreshManager: RefreshManager` used by the request handler; `/health` gains a `trust` block.

This task changes wiring only. The DID-resolution behavior stays identical; the only observable change is `/health` now reports `trust` and the process kicks a background refresh.

- [ ] **Step 1: Replace the trust-init block with a TrustState holder**

In `src/server.ts`, add imports near the existing ones:

```ts
import { RefreshManager, type TrustState } from './trust-refresh.js'
```

Replace this existing block:

```ts
const registry = new TrustRegistry(TRUST_STORE)
try {
  registry.load()
} catch (err) {
  console.warn(`[did:pki] Trust store not loaded: ${err instanceof Error ? err.message : err}`)
}
const pkiResolver = new DidPkiResolver(registry)
const snsResolver = new DidSnsResolver()
const crlRevocation = new CrlRevocationService(TRUST_STORE)

const pkiDids = pkiResolver.listDids()
log('info', `[did:pki] Loaded ${pkiDids.length} DIDs from trust store`)
```

with:

```ts
// Cold start from the baked snapshot — the resolver is never empty even if
// the first network refresh fails.
const bakedRegistry = new TrustRegistry(TRUST_STORE)
try {
  bakedRegistry.load()
} catch (err) {
  console.warn(`[did:pki] Baked trust store not loaded: ${err instanceof Error ? err.message : err}`)
}
const bakedPki = new DidPkiResolver(bakedRegistry)
const state: TrustState = {
  registry: bakedRegistry,
  pkiResolver: bakedPki,
  crl: new CrlRevocationService(TRUST_STORE),
  meta: { source: 'baked', version: 'baked', didCount: bakedPki.listDids().length, lastRefreshAt: null },
  tempDir: null,
}
const snsResolver = new DidSnsResolver()

const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS || 21_600_000) // 6h
const REFRESH_FLOOR_FRACTION = Number(process.env.REFRESH_FLOOR_FRACTION || 0.9)
const REFRESH_DEBOUNCE_MS = Number(process.env.REFRESH_DEBOUNCE_MS || 30_000)
const refreshManager = new RefreshManager(state, {
  floorFraction: REFRESH_FLOOR_FRACTION,
  debounceMs: REFRESH_DEBOUNCE_MS,
})

log('info', `[did:pki] Cold start: ${state.meta.didCount} DIDs from baked snapshot`)
```

- [ ] **Step 2: Point the request handler at the holder**

In `handleRequest`, change the two call sites that use the old consts:

Replace `result = pkiResolver.resolve(did)` with `result = state.pkiResolver.resolve(did)`.

Replace `const result = await crlRevocation.getRevocation(ca)` with `const result = await state.crl.getRevocation(ca)`.

- [ ] **Step 3: Extend the /health payload**

In the health-check branch, replace the existing `sendJson(res, 200, { ... pkiDids: pkiDids.length })` object with:

```ts
    sendJson(res, 200, {
      status: 'ok',
      driver: 'attestto-did-resolver',
      version: '0.1.0',
      supportedMethods: ['pki', 'sns'],
      pkiDids: state.meta.didCount,
      trust: {
        source: state.meta.source,
        trustVersion: state.meta.version,
        didCount: state.meta.didCount,
        lastRefreshAt: state.meta.lastRefreshAt,
      },
    })
```

- [ ] **Step 4: Kick startup + scheduled refresh after the server starts listening**

Find the existing `server.listen(PORT, ...)` call near the bottom of `src/server.ts`. Immediately after it, add:

```ts
// Pull the latest published trust data shortly after boot (non-blocking), then
// on a fixed interval. Failures are logged and leave the baked snapshot in place.
refreshManager.refresh('npm', 'startup')
  .then((r) => log(r.ok ? 'info' : 'warn', `[did:pki] Startup refresh: ${r.reason}`, { didCount: r.didCount }))
  .catch((err) => log('warn', `[did:pki] Startup refresh threw: ${err instanceof Error ? err.message : err}`))

setInterval(() => {
  refreshManager.refresh('npm', 'scheduled')
    .then((r) => log(r.ok ? 'info' : 'warn', `[did:pki] Scheduled refresh: ${r.reason}`, { didCount: r.didCount }))
    .catch((err) => log('warn', `[did:pki] Scheduled refresh threw: ${err instanceof Error ? err.message : err}`))
}, REFRESH_INTERVAL_MS).unref()
```

- [ ] **Step 5: Build to verify the refactor type-checks**

Run: `npx tsc --noEmit`
Expected: no errors. (If `tsc` reports unused `pkiDids`, confirm every old reference was replaced.)

- [ ] **Step 6: Run the full test suite**

Run: `npm test`
Expected: all tests pass (existing crl/normalize + Task 1 & 2 suites).

- [ ] **Step 7: Commit**

```bash
git add src/server.ts
git commit --no-gpg-sign -m "refactor(server): TrustState holder + startup/scheduled refresh + health status — ATT-1063"
```

---

### Task 4: Authenticated refresh webhook (`POST /admin/refresh`)

**Files:**
- Modify: `src/server.ts`
- Create: `src/__tests__/admin-refresh.test.ts`
- Create: `src/admin-auth.ts` (isolated, testable auth check)

**Interfaces:**
- Produces: `function checkBearer(authHeader: string | undefined, secret: string | undefined): { ok: boolean; status: number }` in `src/admin-auth.ts` — pure, unit-testable, constant-time compare.

- [ ] **Step 1: Write the failing test for the auth check**

Create `src/__tests__/admin-refresh.test.ts`:

```ts
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -- --test-name-pattern='checkBearer'`
Expected: FAIL — `Cannot find module '../admin-auth.js'`.

- [ ] **Step 3: Implement `src/admin-auth.ts`**

```ts
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test -- --test-name-pattern='checkBearer'`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire the endpoint into `src/server.ts`**

Add near the other env constants:

```ts
const REFRESH_SECRET = process.env.REFRESH_SECRET
```

Add the import at the top:

```ts
import { checkBearer } from './admin-auth.js'
```

In `handleRequest`, add this branch BEFORE the `/1.0/identifiers/` branch:

```ts
  // Authenticated manual/webhook refresh. POST /admin/refresh { "source": "npm" | "main" }
  if (url.pathname === '/admin/refresh' && method === 'POST') {
    const auth = checkBearer(req.headers.authorization, REFRESH_SECRET)
    if (!auth.ok) {
      sendPlainJson(res, auth.status, auth.status === 503
        ? { error: 'Refresh endpoint disabled (REFRESH_SECRET not set)' }
        : { error: 'Unauthorized' })
      return
    }
    let source: 'npm' | 'main' = 'npm'
    try {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(c as Buffer)
      if (chunks.length) {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf-8'))
        if (body?.source === 'main' || body?.source === 'npm') source = body.source
      }
    } catch {
      // Empty or malformed body → default source 'npm'.
    }
    refreshManager.refresh(source, 'webhook')
      .then((r) => log(r.ok ? 'info' : 'warn', `[did:pki] Webhook refresh: ${r.reason}`, { didCount: r.didCount }))
      .catch((err) => log('warn', `[did:pki] Webhook refresh threw: ${err instanceof Error ? err.message : err}`))
    sendPlainJson(res, 202, { accepted: true, source })
    return
  }
```

- [ ] **Step 6: Build + full test run**

Run: `npx tsc --noEmit && npm test`
Expected: no type errors; all tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/admin-auth.ts src/__tests__/admin-refresh.test.ts src/server.ts
git commit --no-gpg-sign -m "feat(server): authenticated POST /admin/refresh webhook — ATT-1063"
```

---

### Task 5: Cross-repo CI trigger + env docs

**Files:**
- Create (in **attestto-trust**): `/Users/eduardochongkan/Attestto/attestto-trust/.github/workflows/notify-resolver.yml`
- Modify (in **attestto-did-resolver**): `README.md` (document new env vars + the `/admin/refresh` endpoint)

This task spans two repos. Commit each repo separately. Neither is pushed — the human gate reviews both before anything goes live.

- [ ] **Step 1: Create the attestto-trust notify workflow**

Create `/Users/eduardochongkan/Attestto/attestto-trust/.github/workflows/notify-resolver.yml`:

```yaml
name: Notify resolver of trust changes

on:
  push:
    branches: [main]
    paths:
      - 'countries/**'

jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - name: POST /admin/refresh (source=main)
        env:
          SECRET: ${{ secrets.RESOLVER_REFRESH_SECRET }}
        run: |
          if [ -z "$SECRET" ]; then
            echo "RESOLVER_REFRESH_SECRET not set — skipping notify"
            exit 0
          fi
          curl --fail --silent --show-error --retry 3 --max-time 30 \
            -X POST https://resolver.attestto.com/admin/refresh \
            -H "Authorization: Bearer $SECRET" \
            -H "Content-Type: application/json" \
            -d '{"source":"main"}'
```

- [ ] **Step 2: Commit the workflow in attestto-trust (explicit path, no -A)**

```bash
cd /Users/eduardochongkan/Attestto/attestto-trust
git add .github/workflows/notify-resolver.yml
git commit --no-gpg-sign -m "ci: notify resolver /admin/refresh on countries/** change — ATT-1063"
cd /Users/eduardochongkan/Attestto/attestto-did-resolver
```

- [ ] **Step 3: Document the env vars + endpoint in the resolver README**

In `/Users/eduardochongkan/Attestto/attestto-did-resolver/README.md`, find the environment-variable table (the row for `TRUST_STORE_PATH`) and add these rows beneath it:

```markdown
| `REFRESH_SECRET` | *(unset → `/admin/refresh` returns 503)* | Bearer token required by `POST /admin/refresh`. Set as a Fly secret; mirror the same value into the attestto-trust GitHub Actions secret `RESOLVER_REFRESH_SECRET`. |
| `REFRESH_INTERVAL_MS` | `21600000` (6h) | Interval for the scheduled npm pull of `@attestto/trust`. |
| `REFRESH_FLOOR_FRACTION` | `0.9` | A refresh is accepted only if its DID count is ≥ this fraction of the current count. |
| `REFRESH_DEBOUNCE_MS` | `30000` | Coalesce refreshes triggered within this window. |
```

Then add a short subsection after that table:

```markdown
### Auto-refresh

The resolver loads the baked `trust-store/` snapshot at boot, then pulls the latest
`@attestto/trust` from npm shortly after startup and every `REFRESH_INTERVAL_MS`. A merge to
`main` in attestto-trust also triggers an immediate refresh via `POST /admin/refresh`
(authenticated with `REFRESH_SECRET`, body `{"source":"main"}`). A fetch that fails or falls
below the sanity floor leaves the current data untouched. `GET /health` reports the live
`trust.source`, `trust.trustVersion`, `trust.didCount`, and `trust.lastRefreshAt`.
```

- [ ] **Step 4: Commit the README (explicit path)**

```bash
git add README.md
git commit --no-gpg-sign -m "docs: document trust auto-refresh env vars + endpoint — ATT-1063"
```

---

## Deployment (human-gated — do NOT run during implementation)

After review, the maintainer runs these; the implementer must NOT:

1. `fly secrets set REFRESH_SECRET=<value>` on the resolver app.
2. Add the same value as the `RESOLVER_REFRESH_SECRET` GitHub Actions secret in attestto-trust.
3. `cd attestto-did-resolver && fly deploy`.
4. Push both repos (`git push`) once reviewed.
5. Verify: `curl https://resolver.attestto.com/health` shows a `trust` block with `source: "npm"` and a non-zero `didCount`; merge a trivial `countries/**` change and confirm a webhook refresh in logs.
