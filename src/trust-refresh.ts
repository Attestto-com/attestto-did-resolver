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
    if (source !== 'main') {
      const since = this.now() - this.lastAttemptAt
      if (this.lastAttemptAt !== 0 && since < this.debounceMs) {
        return Promise.resolve({ ok: false, source, reason: `debounced (${since}ms < ${this.debounceMs}ms)` })
      }
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
