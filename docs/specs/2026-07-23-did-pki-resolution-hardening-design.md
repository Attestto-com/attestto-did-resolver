# did:pki Resolution Hardening — Design (ATT-1070)

**Date:** 2026-07-23 (rev. 2026-07-24 after live verification)
**Repos:** `attestto-did-resolver` (canonical derivation + resolution), `attestto-trust` (regenerates `did.json`), `attestto-verify` (constructs query DIDs)
**Ticket:** ATT-1070
**Status:** Design, diagnosis re-verified against live resolver

## Problem
A subset of `did:pki` identifiers fail to resolve (`notFound`) even though the certificate is in the trust store. Confirmed repros:
- `did:pki:es:ac-camerfirma:camerfirma-for-legal-persons:2016`
- `did:pki:de:atos-information-technology:hba-qca1`

Most identifiers resolve; only subjects with punctuation/version tokens fail (~4%).

## Verified root cause (2026-07-24)

**It is derivation inconsistency, not data loss.** Two facts, confirmed against the live resolver and the code:

1. **The resolver re-derives, it does not read `did.json`.** `registry.ts:106` calls `derivePathKey(cn, org, cc)` on each manifest cert at load time and indexes by `cc:pathKey`. Resolution (`pki-resolver.ts:37`) parses the incoming DID into `(countryCode, caPath)` and matches by `cc:pathKey`. So a match requires the **client's** parsed path to equal the **resolver's** re-derived path.

2. **`SEPARATOR_PATTERNS` produces stray segments.** `normalize.ts:30,251` splits a CN on `[' - ', ' / ', ' – ', ' — ']`. `AC CAMERFIRMA FOR LEGAL PERSONS - 2016` becomes two segments → a trailing `:2016`. A client that folds the year to `…persons-2016` parses to a different path and misses. Three independent derivations (`normalize.ts`, trust `refresh-did-pki.mjs` which imports `dist/normalize.js`, and verify `pki-did-derivation.ts`) can each drift.

**What is NOT wrong (verified):** generation-grouping. The registry groups multiple certs per key as `RegistryEntry[]` (`registry.ts:32-35`). Live check: `did:pki:it:ministero-dellinterno:national-root-ca-for-the-italian-electronic-identity-card` returns ONE DID document with BOTH `#key-2016` and `#key-2024`. The 942-unique-vs-1106-cert "gap" is the correct count of unique CA identities across key rotations. **The earlier §2 (append `sha256` to every collision) is REMOVED — it would shatter correct generation-grouping.**

## Design

Two coordinated changes plus a lockstep migration. No new disambiguation.

### 1. Canonical slug rule (`normalize.ts`, single source of truth)
- Each path segment matches `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$` (lowercase alphanumerics + internal hyphens). No periods, no other punctuation. Matches `parser.ts` `SEGMENT_REGEX`.
- Transliterate accents to ASCII, lowercase, trim.
- **Remove `SEPARATOR_PATTERNS` stray-splitting.** Replace every run of non-`[a-z0-9]` chars (spaces, periods, dashes, slashes, parens) with a single hyphen; collapse repeats; trim edge hyphens. So `… FOR LEGAL PERSONS - 2016` → one segment `camerfirma-for-legal-persons-2016`; `ATOS.HBA-qCA1` → `hba-qca1`. Version/generation tokens (`2016`, `g2`, `qca1`) live INSIDE the CA segment as `-2016`, never as their own segment.
- **Path shape:** `did:pki:<cc>:<org-slug>:<ca-slug>` — the O-derived segment (omitted for `COUNTRY_AUTHORITIES`) plus one CN-derived segment. Country-authority orgs still omit the O segment.

### 2. One derivation used everywhere (kill cross-impl drift)
- `normalize.ts::deriveDid` is the ONLY canonical algorithm. The resolver registry, trust `refresh-did-pki.mjs` (already imports `dist/normalize.js`), and verify MUST all use it. Verify's `pki-did-derivation.ts` is either replaced by importing the published derivation or aligned char-for-char (and covered by a shared test vector set), so the DID a verifier constructs equals the DID the resolver derives.
- Optional robustness: resolution may additionally consult the existing `byDid` map with a lowercased-key fallback, but with canonical derivation applied consistently the primary `cc:pathKey` lookup already matches; opaque `byDid` is a belt-and-suspenders fallback, not the fix.

### 3. Generation-grouping is preserved (explicit non-change)
Multiple certs sharing a canonical DID remain grouped as multiple `verificationMethod`s / `generations` on one DID document. This is correct did:pki modeling (a CA identity persists across key rotations) and must not change.

## Migration (one-time, versioned, lockstep)
A `did:pki` string is a stable identifier, so re-slugging the ~4% stray-segment cases is a breaking change to those identifiers — acceptable now (young directory), done deliberately:
1. Land the `normalize.ts` slug change + tests in `attestto-did-resolver`; build `dist/`.
2. Regenerate **every** country's `did.json` in `attestto-trust` against that `dist/`, one pass.
3. Align/replace verify's `pki-did-derivation.ts` to the canonical algorithm; add the shared test-vector suite to all three repos.
4. Republish `@attestto/trust` (minor) and redeploy the resolver from the matching commit so all three surfaces derive identically.
5. Freeze the algorithm after this pass.

## Testing
- **Repro cases resolve:** the Camerfirma and ATOS identifiers return a DID Document. Explicit regression tests.
- **Whole-registry round-trip:** for every entry the resolver builds, resolving its derived DID returns it. The tripwire that would have caught this.
- **Generation-grouping intact:** the Italy CIE DID still returns both `#key-2016` and `#key-2024` after the change; a test asserts multi-generation DIDs keep all keys.
- **Cross-impl parity:** a shared fixture of (subject, expected-DID) vectors passes identically in resolver, trust-refresh, and verify.
- **Charset:** every generated segment matches `SEGMENT_REGEX`; no stray segments.

## Non-goals
- No change to did:pki method semantics or DID Document contents beyond slug canonicalization.
- No sha256 disambiguation (removed — would break correct generation-grouping).
- No dual-resolution v1/v2 alias layer (clean versioned re-slug; add later only if external refs demand it).
- No change to did:sns.

## Rollout order
1. `normalize.ts` slug change + tests in `attestto-did-resolver`; build `dist/`.
2. Regenerate all `did.json` in `attestto-trust`; run trust tests.
3. Align verify derivation + shared vectors.
4. Publish `@attestto/trust` (minor), redeploy resolver from the matching commit.
5. Verify the whole-registry round-trip + repro cases against the live resolver.
