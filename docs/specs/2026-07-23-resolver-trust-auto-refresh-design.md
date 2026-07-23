# Resolver Trust-Store Auto-Refresh — Design

**Date:** 2026-07-23
**Ticket:** ATT-1063
**Repo:** attestto-did-resolver

## Problem

The resolver serves `did:pki:*` from an in-memory registry built by `TrustRegistry.load()`,
which reads a local `TRUST_STORE_PATH` (`trust-store/countries/`). That directory is a
**gitignored mirror** of [attestto-trust](https://github.com/Attestto-com/attestto-trust),
copied by hand into the Docker image before `fly deploy`. Consequently:

- A cert change in attestto-trust is invisible to the resolver until someone re-copies the
  mirror **and** redeploys.
- The mirror silently drifts. This caused a production incident where Germany (101 CAs) and
  Italy (231 CAs) were promoted to `current/` in attestto-trust but the mirror still held only
  their `raw/`/`staging/` folders, so `TrustRegistry.loadCountry()` (`if (!existsSync(manifestPath)) return`)
  skipped both countries and every `did:pki:de:*` / `did:pki:it:*` returned 404.

## Goal

Trust changes reach the live resolver **without a manual redeploy**, via two mechanisms:

1. **Scheduled + startup pull** — the resolver fetches the latest trust data on boot and on a
   fixed interval, rebuilding its registry in place.
2. **Webhook-triggered refresh** — a merge to `main` in attestto-trust POSTs to the resolver,
   which refreshes immediately.

## Non-Goals

- Changing the DID derivation algorithm (`normalize.ts`) — unchanged.
- Changing the DID resolution response shape — unchanged.
- Per-country partial refresh — a refresh always rebuilds the full registry (simpler, and the
  full dataset is small).
- Persisting fetched data to disk beyond a working directory — refresh is in-memory; the baked
  snapshot remains only as a cold-start fallback.

## Source of Truth

**Default source: the npm published package `@attestto/trust`** (immutable, versioned — better
audit story). **Fallback/override: GitHub `main`**, used only when a webhook explicitly requests
`source: "main"` (e.g. to serve a merge that is not yet npm-published). Both are gzipped tarballs.

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              server.ts (HTTP)                │
                    │  handler reads state.holder per-request      │
                    └───────────────┬─────────────────────────────┘
                                    │ reads
                    ┌───────────────▼─────────────────────────────┐
                    │   TrustState holder (mutable references)     │
                    │   { registry, pkiResolver, crl, meta }       │
                    └───────────────▲─────────────────────────────┘
                                    │ atomic swap on success
        ┌───────────────────────────┴──────────────────────────┐
        │             RefreshManager (trust-refresh.ts)         │
        │  fetch → build new registry+crl → validate floor →    │
        │  swap; debounce + in-flight lock; keep old on failure │
        └───────┬───────────────────────────────┬──────────────┘
                │ fetchNpm() (default)           │ fetchGitHubMain() (webhook override)
        ┌───────▼────────────────────────────────▼──────────────┐
        │              trust-source.ts (fetch + extract)         │
        │  npm registry tarball / GitHub codeload tarball →      │
        │  extract countries/ to a temp dir → return path        │
        └────────────────────────────────────────────────────────┘

  Triggers into RefreshManager:
    - startup (async, after cold-start baked load)
    - setInterval (REFRESH_INTERVAL_MS, default 6h) → fetchNpm
    - POST /admin/refresh (authenticated) → fetchNpm or fetchGitHubMain
```

## Components

### `src/trust-source.ts` — fetch + extract

- `fetchNpm(pkg = "@attestto/trust"): Promise<{ countriesDir: string; version: string; cleanup(): void }>`
  Resolve the latest version from `https://registry.npmjs.org/<pkg>` (`dist-tags.latest` → `versions[v].dist.tarball`),
  download the `.tgz`, extract `package/countries/` into a fresh temp dir. Returns the extracted
  `countries/` path, the resolved version string, and a `cleanup()` that removes the temp dir.
- `fetchGitHubMain(repo = "Attestto-com/attestto-trust"): Promise<{ countriesDir: string; ref: string; cleanup(): void }>`
  Download `https://codeload.github.com/<repo>/tar.gz/refs/heads/main`, extract
  `<repo-basename>-main/countries/` into a fresh temp dir. Returns the extracted path, `ref = "main"`, and `cleanup()`.
- Extraction uses the **`tar`** npm package (the one new dependency). Temp dirs are created under
  `os.tmpdir()` via `fs.mkdtempSync`.

### `src/trust-refresh.ts` — orchestration

- `class RefreshManager` constructed with the `TrustState` holder and config (sanity-floor
  fraction, debounce ms).
- `async refresh(source: "npm" | "main", reason: string): Promise<RefreshResult>`:
  1. If a refresh ran within the debounce window (default 30s) or one is in-flight, coalesce
     (return the in-flight promise or a `skipped` result).
  2. Fetch via the chosen source.
  3. Build a **new** `TrustRegistry` pointed at the extracted dir and call `.load()`; build a
     new `CrlRevocationService` at the same dir.
  4. **Validate the sanity floor:** new registry must load ≥ 1 country **and** its DID count
     must be ≥ `floorFraction × currentDidCount` (default 0.9). The first successful load
     (currentDidCount 0 at boot) passes any non-zero count.
  5. On pass: atomically swap `state.registry`, `state.pkiResolver`, `state.crl`, and
     `state.meta` ( `{ source, version|ref, didCount, lastRefreshAt }` ). Then `cleanup()` the
     **previous** temp dir (never the just-installed one).
  6. On any failure: log a warning, `cleanup()` the failed temp dir, leave live references
     untouched. Never throws to the caller in a way that crashes the process.
- `RefreshResult = { ok: boolean; source; version?: string; didCount?: number; reason: string }`.

### `src/server.ts` — holder refactor + wiring

- Replace the module-level `registry` / `pkiResolver` / `crlRevocation` consts with a single
  mutable `state: TrustState` object. The request handler reads `state.pkiResolver` /
  `state.crl` **per request** instead of closing over consts.
- **Cold start:** load the baked snapshot at `TRUST_STORE_PATH` into `state` exactly as today
  (so a fetch outage never leaves the resolver empty).
- After cold start, fire `refreshManager.refresh("npm", "startup")` **without awaiting** (boot
  is not blocked on network).
- `setInterval(() => refreshManager.refresh("npm", "scheduled"), REFRESH_INTERVAL_MS)`.
- **`POST /admin/refresh`:** authenticate with a bearer token — compare
  `Authorization: Bearer <token>` against `REFRESH_SECRET` using `crypto.timingSafeEqual`
  (length-guarded). Missing/mismatched → `401`. Missing `REFRESH_SECRET` in env → `503`
  (endpoint disabled). Parse optional JSON body `{ source?: "npm" | "main" }` (default `"npm"`).
  Kick `refreshManager.refresh(source, "webhook")` async; respond `202 { accepted: true }`.
- **Status:** extend the existing `GET /health` response with
  `{ trust: { source, version, didCount, lastRefreshAt } }` from `state.meta` (no separate
  admin-status endpoint — keep the surface small).

## Cross-Repo: attestto-trust CI trigger

New file in **attestto-trust**: `.github/workflows/notify-resolver.yml`.

- Trigger: `push` to `main` with `paths: ['countries/**']`.
- Step: `curl -X POST https://resolver.attestto.com/admin/refresh
  -H "Authorization: Bearer ${{ secrets.RESOLVER_REFRESH_SECRET }}"
  -H "Content-Type: application/json" -d '{"source":"main"}'` with `--fail --retry 3`.
- The secret `RESOLVER_REFRESH_SECRET` is stored as a GitHub Actions secret in attestto-trust and
  as the `REFRESH_SECRET` Fly secret on the resolver — the same value.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `TRUST_STORE_PATH` | `../trust-store/countries` | Cold-start baked snapshot (unchanged) |
| `REFRESH_SECRET` | *(unset → webhook disabled, 503)* | Bearer token for `POST /admin/refresh` |
| `REFRESH_INTERVAL_MS` | `21600000` (6h) | Scheduled npm-pull interval |
| `TRUST_NPM_PKG` | `@attestto/trust` | npm package to pull |
| `TRUST_GITHUB_REPO` | `Attestto-com/attestto-trust` | GitHub repo for the `main` fallback |
| `REFRESH_FLOOR_FRACTION` | `0.9` | Min new-DID-count as a fraction of current, to accept a swap |
| `REFRESH_DEBOUNCE_MS` | `30000` | Coalesce refreshes within this window |

## Error Handling

- **Fetch failure / timeout:** log `warn`, keep old data. Scheduled retries continue.
- **Truncated or malformed tarball:** extraction throws → caught → keep old data, cleanup temp.
- **Sanity floor not met:** reject swap, log `warn` with old vs new counts, keep old data. This is
  the guard against a partial/empty upstream.
- **Concurrent triggers:** in-flight lock returns the running promise; debounce window drops
  redundant near-simultaneous triggers.
- **Webhook abuse:** auth required; unauthenticated calls never touch the network. Debounce caps
  fetch frequency regardless of caller volume.

## Testing

Node's built-in `node:test` + `tsx` (repo pattern `src/**/*.test.ts`), **no network** — use
captured fixture tarballs committed under `src/__fixtures__/`.

1. `trust-source.test.ts` — extract a fixture npm `.tgz` and a fixture GitHub `.tar.gz`; assert
   the returned `countriesDir` contains `de/current/manifest.json`; assert `cleanup()` removes the
   temp dir; assert the npm version / github ref are parsed.
2. `trust-refresh.test.ts` —
   - Happy path: fresh dir with N DIDs → swap; `state.meta.didCount === N`.
   - Sanity floor: a fixture dir with a **collapsed** count (< 90% of current) → swap rejected,
     old references retained.
   - Fetch throws → old references retained, no crash.
   - Debounce: two refreshes within the window → second coalesces.
3. `server-refresh.test.ts` (or extend existing server tests) —
   - `POST /admin/refresh` with no/invalid bearer → 401; with `REFRESH_SECRET` unset → 503.
   - With valid bearer → 202 and the manager is invoked with the requested source.
   - `/health` reports `trust.didCount` / `source` / `lastRefreshAt`.

## Rollout

1. Ship the resolver changes; deploy with `REFRESH_SECRET` set as a Fly secret. Baked snapshot
   still loads at boot, so behavior is unchanged if fetch fails.
2. Add `RESOLVER_REFRESH_SECRET` to attestto-trust GitHub Actions secrets; merge the
   `notify-resolver.yml` workflow.
3. Verify: merge a trivial `countries/**` change → observe a webhook refresh in resolver logs and
   an updated `didCount` in `/health`.
