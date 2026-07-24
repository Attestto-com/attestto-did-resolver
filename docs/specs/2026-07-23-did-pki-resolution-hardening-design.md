# did:pki Resolution Hardening — Design (ATT-1070)

**Date:** 2026-07-23
**Repos:** `attestto-did-resolver` (resolution + canonical derivation) and `attestto-trust` (regeneration of `countries/<cc>/did.json`)
**Ticket:** ATT-1070
**Status:** Design, pending review

## Problem

A subset of `did:pki` identifiers fail to resolve (`notFound`, sometimes `500`) even though the certificate is present in the trust store and the identifier is listed in the country's `did.json`. Confirmed repro cases:

- `did:pki:de:atos-information-technology:hba-qca1` (cert subject `ATOS.HBA-qCA1`)
- `did:pki:es:ac-camerfirma:camerfirma-for-legal-persons:2016` (cert subject `AC CAMERFIRMA FOR LEGAL PERSONS - 2016`)

Most identifiers resolve (Costa Rica, Italy, ~96% of Spain); only subjects with irregular punctuation/structure fail.

## Root cause

The resolver **re-derives** a structured key from the certificate/DID at resolve time rather than matching the identifier against the registry it already loaded. Two failure mechanisms compound:

1. **The derivation is a heuristic that produces surprising segment structure.** `src/normalize.ts` splits the Common Name on `SEPARATOR_PATTERNS = [' - ', ' / ', ' – ', ' — ']` into separate colon-segments. So `AC CAMERFIRMA FOR LEGAL PERSONS - 2016` becomes two segments `camerfirma-for-legal-persons` + `2016`, i.e. a trailing `:2016`. Together with O-name stripping, version/generation suffix rules, and country-authority omission, the derivation is hard to reproduce and easy to get wrong.

2. **Generate-time and resolve-time derivations can drift.** `attestto-trust/scripts/refresh-did-pki.mjs` imports `deriveDid` from `../attestto-did-resolver/dist/normalize.js` to write `did.json`. The deployed resolver runs its own build of the same function. Any version skew between the local `dist/` used to regenerate `did.json` and the deployed resolver yields identifiers that no longer match. The Spain promotion regenerated `es/did.json` against a local build; the deployed resolver derived a different key for the punctuation cases, so the stored string is unresolvable.

The identifier is in `did.json`, the resolver loaded it (it is counted in `didCount`), but the resolve-time key does not equal the stored key.

## Design

Three coordinated changes. Generation and resolution contracts must change together, or drift returns.

### 1. Canonical slug rule (shared `deriveDid`, `src/normalize.ts`)

Standardize path segments to a single, punctuation-free charset and stop splitting on separators.

- **Charset:** each segment matches `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$` (lowercase alphanumerics and internal hyphens only). No periods, no other punctuation. This already matches `parser.ts` `SEGMENT_REGEX`.
- **Transliterate** accents to ASCII (keep the existing `TRANSLITERATION` map), lowercase, trim.
- **Do NOT split on ` - `, ` / `, ` – `, ` — `.** Remove `SEPARATOR_PATTERNS` segment-splitting. Instead, replace every run of non-`[a-z0-9]` characters (spaces, periods, dashes, slashes, parentheses) with a single hyphen, then collapse repeated hyphens and trim edge hyphens. So:
  - `AC CAMERFIRMA FOR LEGAL PERSONS - 2016` → segment `camerfirma-for-legal-persons-2016` (the year folds into the one segment with a hyphen, not a stray `:2016`).
  - `ATOS.HBA-qCA1` → `hba-qca1` (after O-name removal), periods to hyphens then collapsed.
- **Path shape:** `did:pki:<cc>:<org-slug>:<ca-slug>` — at most the O-derived segment plus one CN-derived segment. Country-PKI-authority orgs still omit the O segment (keep `COUNTRY_AUTHORITIES`). Do not emit more than these segments; disambiguating tokens (year, generation number) live inside `<ca-slug>` as `-2016`, `-g2`, `-qca1`, never as their own segment.

### 2. Uniqueness must survive normalization (deterministic disambiguation)

Special characters are often doing disambiguation work: Camerfirma issues one "for legal persons" cert per year; ATOS ships `HBA-qCA1..qCA8`. Flattening must not merge distinct certs.

- Keep the distinguishing token inside the slug (`-2016`, `-qca1`, `-g2`) — the slug rule above preserves it since it only converts punctuation to hyphens rather than dropping trailing tokens.
- If two certs in the same country still collide on the full DID after slugging, append `-<sha256[:8]>` to the later one, deterministically ordered by SHA-256. Never silently overwrite or merge. Emit a build-time warning listing any collision so it is visible.

### 3. Resolve by opaque exact-match against the registry (`src/parser.ts`, resolution path)

Stop re-deriving at resolve time. The published `did.json` set is the single source of truth.

- At startup, build a `Map<string, Cert>` from every country's `did.json` (the registry the resolver already loads), keyed by the exact DID string, plus a second lowercased-key map for a forgiving fallback.
- **Resolution:** validate only the `^did:pki:[a-z]{2}:` prefix and that the remainder is a non-empty `:`-joined path of valid segments; then look the full string up in the exact map, and if absent, the lowercased map. Return the mapped cert's DID Document, or `notFound`. No character-class re-normalization of the incoming identifier beyond lowercasing for the fallback.
- Treat `<rest>` as an **opaque, variable-length `:`-separated path**. Segment count is not fixed and not re-parsed into org/CN roles at resolve time. `formatDid`/`parseDid` role-parsing (generation extraction, etc.) is retained only where the resolver needs structure for output metadata, not for lookup.
- `deriveDid` remains the canonical generator (spec §7) used by `refresh-did-pki` and for offline "derive a DID from a certificate" use. It is simply no longer on the resolve-time hot path.

## Migration (one-time, versioned)

A `did:pki` string is a stable identifier, so re-slugging is a breaking change to already-published identifiers. Acceptable now (young directory, few external references), but done deliberately:

1. Bump a derivation version constant in `normalize.ts` (e.g. `DERIVATION_VERSION = 2`) and record it in each `did.json` header.
2. Rebuild `attestto-did-resolver` and regenerate **every** country's `did.json` in one pass (`refresh-did-pki.mjs` across all `countries/*`), against the same freshly built `dist/`.
3. Republish `@attestto/trust` (minor bump) and redeploy the resolver from the same commit, so generate-time and resolve-time derivations are guaranteed identical.
4. Freeze the algorithm after this pass. Future certs slug deterministically; the identifier for an existing cert must not change again.

## Testing

- **Repro cases resolve:** `did:pki:de:atos-information-technology:hba-qca1` and the canonical Camerfirma identifier both return a DID Document. Add both as explicit regression tests.
- **Round-trip invariant:** for every entry in every `did.json`, resolving that exact string returns the matching certificate. A single test iterates the whole registry (this is the tripwire that would have caught this bug).
- **No collisions:** regenerating all countries produces zero duplicate DID strings; any disambiguation applied is logged and asserted stable across two runs.
- **Charset:** every generated segment matches `SEGMENT_REGEX`; no periods or other punctuation survive.
- **Generate == resolve:** a test derives DIDs from a sample of certs via `deriveDid` and confirms the resolver resolves each, guarding against future drift.

## Non-goals

- No change to the did:pki *method* semantics or DID Document contents, only how identifiers are slugged and looked up.
- No attempt to preserve old (v1) identifier strings; this is a clean versioned re-slug, not a dual-resolution compatibility layer. (If external references later require it, a v1→v2 alias map can be added, but it is out of scope here.)
- No change to did:sns resolution.

## Rollout order (avoids a window where the two surfaces disagree)

1. Land the `normalize.ts` slug change + `parser.ts` opaque-match change + tests in `attestto-did-resolver`; build `dist/`.
2. Regenerate all `did.json` in `attestto-trust` against that `dist/`; run the full trust test suite.
3. Publish `@attestto/trust` (minor bump) and deploy the resolver from the matching commit.
4. Verify the whole-registry round-trip against the live resolver.
