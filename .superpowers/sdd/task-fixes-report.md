# ATT-1063 Fix Report — trust-store auto-refresh hardening

## I-1: temp-dir leak in `extractTarball` when `tar.x` throws

**Finding:** `mkdtempSync` allocates a temp dir before extraction. On a malformed tarball, `tar.x` rejects and the temp dir was orphaned — the catch branch in `doRefresh` only cleaned `fetched.tempDir`, which is only set *after* successful extraction.

**Fix:** `src/trust-source.ts` — added an inner `try/catch` around `tar.x` that calls `rmSync(tempDir, { recursive: true, force: true })` before rethrowing. Kept `tgzPath` cleanup in `finally`.

**Test:** `src/__tests__/trust-source.test.ts` — "extractTarball cleans up temp dir on extraction failure"
- Counts `attestto-trust-*` entries in `os.tmpdir()` before and after a call with `Buffer.from('not a tarball')`
- Asserts count does not increase

**Result:** PASS (was: not present → now GREEN)

---

## I-2: no fetch timeout wedges `RefreshManager.inFlight` forever

**Finding:** Both `fetchNpm` and `fetchGitHubMain` called `fetchImpl(url)` with no timeout. A hung connection left `inFlight` non-null permanently, silently disabling all future refreshes.

**Fix:** `src/trust-source.ts`
- Added module constant: `const FETCH_TIMEOUT_MS = Number(process.env.REFRESH_FETCH_TIMEOUT_MS || 30_000)`
- In `fetchBuffer`: `fetchImpl(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })`
- In `fetchNpm` metadata call: `fetchImpl(metaUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })`

**Tests:** `src/__tests__/trust-source.test.ts`
- "fetchNpm passes AbortSignal to both fetch calls" — injected fetchImpl captures `opts?.signal instanceof AbortSignal` for metadata URL and tarball URL; asserts both true
- "fetchGitHubMain passes AbortSignal to fetch" — same pattern for single call

**Result:** Both PASS (were: not present → now GREEN)

---

## I-3: unbounded request-body read in `/admin/refresh`

**Finding:** `for await (const c of req) chunks.push(c)` had no size cap. Auth-gated, but a valid token bearer could send an arbitrarily large body.

**Fix:**
- New module `src/http-utils.ts` — exports `readBodyCapped(req, limit)`: accumulates chunks, throws `RangeError` if running total exceeds `limit`.
- `src/server.ts` — imports `readBodyCapped`, replaces inline loop with `await readBodyCapped(req, 4096)`. On `RangeError`, responds `413 { error: 'Payload too large' }` via `sendPlainJson`.

**Test:** `src/__tests__/http-utils.test.ts` (4 tests)
- Returns concatenated buffer under limit
- Returns empty buffer for empty body
- Throws RangeError when body exceeds limit
- Exact boundary: 4096 ok, 4097 throws

**Result:** All 4 PASS (new file → GREEN)

---

## M-1: debounce blocks `main` (webhook) refresh behind recent `npm` refresh

**Finding:** `refresh()` applied the debounce window to all sources. A `source:'main'` webhook arriving within 30s of a scheduled npm pull returned `debounced` and did not fetch fresh data — defeating the webhook's purpose.

**Fix:** `src/trust-refresh.ts` — debounce check now wrapped in `if (source !== 'main')`. In-flight lock still applies to both sources.

**Tests:** `src/__tests__/trust-refresh.test.ts`
- "main refresh bypasses debounce window after an npm refresh" — first npm refresh sets debounce clock; 5s later, `main` refresh succeeds (ok: true)
- "npm refresh within debounce window after npm refresh is still debounced" — same setup; second npm refresh returns debounced (ok: false)

**Result:** Both PASS (were: not present → now GREEN)

---

## M-3 (lint): unused `existsSync` import in trust-refresh.test.ts

**Fix:** `src/__tests__/trust-refresh.test.ts` — removed `existsSync` from the `node:fs` import.

---

## tsc result

`npx tsc --noEmit` — clean (no output, exit 0)

---

## npm test output

```
ℹ tests 37
ℹ suites 0
ℹ pass 37
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 449.092583
```

Previous baseline: 28/28. After fixes: 37/37 (+9 new tests, all green).

---

## Files changed

- `src/trust-source.ts` — I-1 (catch+cleanup), I-2 (FETCH_TIMEOUT_MS + AbortSignal on both calls)
- `src/trust-refresh.ts` — M-1 (debounce exempt for `main`)
- `src/server.ts` — I-3 (use `readBodyCapped`, 413 on overflow)
- `src/http-utils.ts` — NEW: `readBodyCapped` helper
- `src/__tests__/trust-source.test.ts` — I-1, I-2 tests
- `src/__tests__/trust-refresh.test.ts` — M-1 tests, M-3 lint fix
- `src/__tests__/http-utils.test.ts` — NEW: I-3 unit tests
