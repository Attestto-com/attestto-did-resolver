---
project_name: 'attestto-did-resolver'
user_name: 'Eduardo'
date: '2026-08-10'
sections_completed: ['technology_stack', 'language', 'framework', 'testing', 'quality', 'workflow', 'dont_miss']
existing_patterns_found: 0
---

# Project Context for AI Agents

_Critical rules for implementing code in this repo. Unobvious details only — not a tutorial._

---

## ⛔ Rule 0 — The published spec is the authority

`did:sns` behaviour is defined by **`../did-sns-spec/did-sns/spec/*.md`** (public, W3C registries pipeline). `did:pki` behaviour is defined by **`did-pki-spec`**.

- A Jira ticket, a Confluence page, a memory note, a prior session's decision, and **this file** do not override the spec. If the model needs to change, the spec changes first.
- **Every behavioural change cites a section** — `§9.2 step 2`, `§7.1`, `§12.6`. A change you cannot cite is a change you are inventing. Enforcement is the test name, not good intentions: the conformance test for a rule carries its section number, so an uncited change is a change with no test.

### When the spec is silent — the procedure

A spec gap is the case that actually happens, and "raise it upstream" alone does not survive a blocked implementer on a deadline. That is how `#key-1` was born. So:

1. **Never invent a value.** Do not synthesise a plausible-looking key, fragment, or field to fill the hole.
2. **Return an explicit signal instead** — an error code from the §9.2 set, or a `degraded`-style flag. The resolver may refuse to answer; it may never answer with something that *looks* authoritative and isn't.
3. **File the gap against `did-sns-spec` with an owner and a date**, and record it below. An undated gap becomes a permanent accepted state — that is the SOC-84 pattern (marked Done on the spec edit, never implemented).

### Open spec gaps

| Gap | Spec | Owner | Filed / expires |
|---|---|---|---|
| §8.5 mandates `#firma-digital` / `#attestto-sign` for Tier 1/2 and defines **no source** for them — not the 160-byte buffer (§10, fully allocated), not the SAS schema (§11), and §9.2 never fetches a document. `Doc Hash` (§10, offset 103) is declared and read by no normative text. | §8.5, §9.2, §10, §11 | Eduardo (spec author) | _TBD — file before this file lands_ |

Until that gap closes, a Tier 1/2 identity has **no conformant verification method**, and the resolver must say so rather than default to the owner wallet.

### Spec pin (freshness — a stale rules file is a defect generator)

These rules were written against **`did-sns-spec` @ `9e04ffc`** (spec v0.4.0). A CI check fails the build when that SHA moves without this file being reviewed. No test catches a stale rules file on its own; this is the external referent that does.

## Technology Stack & Versions

| Layer | Choice | Notes |
|---|---|---|
| Runtime | Node 22 (CI), ESM (`"type": "module"`) | `NodeNext` — **relative imports need explicit `.js` extensions**, even from `.ts` sources |
| Language | TypeScript ~5.6, `strict: true`, ES2022 | `rootDir: src`, `outDir: dist`, `declaration: true` |
| HTTP | Node `http` only — **no framework** | Manual `url.pathname` matching in `src/server.ts` |
| Chain | `@solana/web3.js` ^1.98 | `did:sns` reads `NameRegistry` accounts over a single RPC |
| Trust store | `@attestto/trust` via npm, refreshed at runtime | `did:pki` only; `TRUST_STORE_PATH` env |
| Tests | `node --test` + `tsx`, in `src/__tests__/` | `npm test` |
| Deploy | Fly app `uni-resolver-driver-did-sns` | **Public** at `resolver.attestto.com` |
| Package | `@attestto/did-resolver`, `private: true` | The published standalone driver is `@attestto/did-sns-resolver` — a separate repo |

## Critical Implementation Rules

### Language-Specific Rules

- **Explicit `.js` on every relative import.** `NodeNext` resolution; `import { x } from './foo'` fails at runtime even though the file is `foo.ts`.
- **`strict: true` is on** — no implicit `any`, no unchecked index access assumptions. Prefer narrowing over `as`.
- **Buffer offsets are load-bearing.** `sns-resolver.ts` slices the SNS account by absolute byte offsets (header 0–95, DID metadata 96+, per §10). Never change an offset without quoting the §10 table. Off-by-one here silently yields a valid-looking wrong key.
- **`node:crypto` / `node:fs` imports use the `node:` prefix.** Match the existing style.

### Framework-Specific Rules (there is no framework)

- **Routing is a chain of `if` blocks in `src/server.ts`.** A new endpoint is a new `url.pathname` branch plus a `404` fallthrough check — there is no router to register with.
- **Every response goes through `sendJson`.** Do not call `res.end` directly; the helper sets CORS and content-type consistently.
- **Rate limiting is applied before route dispatch** (`src/rate-limit.ts`) — a new route inherits it automatically. If a route must bypass it, that is a deliberate decision and needs a comment saying why.
- **Resolution logic stays out of `server.ts`.** `sns-resolver.ts` / `pki-resolver.ts` are pure over their inputs (plus the RPC call); the server is transport only. Keeping them pure is what makes them testable — see below.

### Resolution Invariants — convenience index ONLY

> ⚠️ **This table is navigation, not law.** It is a hand-copy of normative text, so it can go stale — and a stale copy inside the file that declares "the spec is the authority" is exactly the drift this repo already suffers from. **If this table and the spec disagree, the spec wins and this table is the bug.** Read the cited section before acting on a row.
>
> The **test** is the enforcement. Each row names the test that holds it; a row with no test is an unenforced claim.

| Rule (read the spec, not this) | Spec | Enforcing test |
|---|---|---|
| Strip a trailing `.sol` **before** depth validation | §9.2 step 2 | `sns-parse.test.ts` |
| `mainnet` / `devnet` / `testnet` with no name → `invalidDid` (reserved selectors, never resolvable names) | §7.1 | `sns-parse.test.ts` |
| `label = 1*(ALPHA / DIGIT / "-")` — no underscore; syntax violation is `invalidDid`, not `notFound` | §7.1 | `sns-parse.test.ts` |
| Max 2 levels (root + one subdomain) | §7.2 | `sns-parse.test.ts` |
| Zero-address owner → `deactivated`. **Liveness is the owner field, not the ACTIVE flag** | §9.2 step 9, §10 note | `sns-resolve.test.ts` |
| No `0x44494401` magic → degraded fallback; resolver **MUST** set `degraded = true` + `warning` | §9.1, §9.2, §12 | `sns-degraded.test.ts` |
| Fragment vocabulary: `#solana-key` / `#ecies-key` / `#firma-digital` / `#attestto-sign` / `#key-agreement` / `#pq-auth-key` / `#pq-kem-key`. Invented fragments (`#key-1`) are non-conformant | §8.5, §12.1 | `sns-document.test.ts` |
| v2 + `HAS_SAS` → follow the SAS UID for issuer-signed claims | §9.2 step 11 | _none yet — unenforced_ |
| Error codes are a closed set: `invalidDid` 400, `notFound` 404, `deactivated` 200, `internalError` 500 | §9.2 | `sns-errors.test.ts` |

- **Error-code discipline matters more than it looks.** `notFound` says "this name isn't registered"; `invalidDid` says "this string isn't a DID." Returning the wrong one tells a verifier to retry something it should reject outright.

### ⛔ SNS is `subdomain.domain` — TWO levels. Settled; not a decision.

Solana Name Service supports a root domain and one level of subdomain. Strip
`.sol`, then count: `attestto` ✅ · `alice.attestto` ✅ · `alice.tenant.attestto`
⛔ — the last has **no PDA to derive**, so it is *impossible*, not merely
disallowed (§7.2). **The tenant IS the domain**: a tenant identity is
`alice.crbank`, never `alice.crbank.attestto`.

`parseSnsDid` returns `tooDeep` for these. When an artefact elsewhere writes three
labels — tier tables, credential examples, handle builders — **the artefact is the
bug**; correct it. Never raise it as an open question and never propose changing
§7.2. Enforcing test: `sns-parse.test.ts` (`§7.2 — two levels maximum`).

### Testing Rules

- 🩸 **The `did:sns` resolver currently has ZERO tests, and CI runs no tests at all.** `.github/workflows/ci.yml` is stub-guard → `tsc --noEmit` → build. `npm test` is never executed. That is why seven spec violations reached a public endpoint.
- ⛔ **PRECONDITION, not an aspiration: the CI `npm test` step lands in the same PR as the first conformance test, or neither lands.** Until CI runs tests, a PR can add tests that never execute — and a green pipeline then actively *signals* conformance nobody checked. That is worse than no CI, because it manufactures confidence.
- 🩸 **`tsconfig.json` excludes `src/**/*.test.ts` and `src/__tests__/**`** — so `tsc --noEmit` never type-checks a test. Type assertions inside specs are not verified. Fix this or know it.
- **A conformance test asserts against a quoted spec line, never against what the code emits.** Put the section number in the test name. A test written by reading the implementation proves the implementation agrees with itself.
- **Prove the test can fail.** For each guard, flip the condition (or mutate the source) once and confirm red before landing it. A test whose colour you cannot explain is not evidence.
- **`sns-resolver.ts` needs an injectable RPC** to be testable. Take the `Connection` (or an `getAccountInfo` port) as a constructor argument rather than building it inline — do this as part of the first test PR, not as a separate refactor.
- Tests live in `src/__tests__/<subject>.test.ts` and use `node:test` + `node:assert/strict`. Fixtures go in `src/__tests__/fixtures/`.

### Code Quality & Style Rules

- **No ESLint or Prettier in this repo.** Match surrounding style by hand: 2-space indent, single quotes, no semicolons omitted (the codebase uses them), `camelCase` functions, `PascalCase` classes.
- **CI runs a stub guard that fails the build** on `TODO`/`FIXME`/`HACK`/`PLACEHOLDER`, `did:example:`, `'fake_'`/`'dummy_'`/`'sample_'`, `alert('`, "coming soon", "not implemented", and `'00000'`. Do not write these — including in comments. Add `stub-guard-ignore` only with a stated reason.
- **Section comments carry the spec citation.** The existing files document algorithms by referencing the method spec; keep that — it is the only thing tying code to authority.

### Development Workflow Rules

- Default branch is `main`; CI runs on PRs to `main`.
- **No `Co-Authored-By` in commit messages.** Never override git identity.
- Commit messages: conventional prefix, then a body explaining *why*, not what.
- **Deploying re-allocates public IPs.** `fly.toml` declares `[http_service]`, and every `fly deploy` re-acquires public IPs (SOC-100). This app is *intentionally* public (SOC-101) — but never assume that for a sibling app.
- `dist/` is committed-adjacent build output — run `npm run build` before deploy; a stale `dist/` means a source fix ships as a no-op.

### Critical Don't-Miss Rules

- **Never invent resolver behaviour to fill a spec gap.** See Rule 0. Raise it upstream.
- **Never publish a key the spec does not define a source for.** The current `#key-1` = owner-wallet default exists because the code needed *a* key and the spec supplied none. That is the failure mode to avoid, not to copy.
- **A degraded document must be labelled as one.** An unregistered SNS domain resolving to a document that looks registered is a downgrade attack (§9.1, §12) — and it has already fooled a reader of this system.
- **Single-RPC resolution is a known first-class threat** (§12.6): a malicious RPC forges the owner key and the resolver emits attacker keys with no visible signal. Multi-provider quorum is the mitigation; do not silently resolve from one provider for high-assurance paths.
- **No PII on-chain and none in logs.** Log the DID and the outcome, never buffer contents or account data.
- **The revocation endpoint takes no serial by design** (`/revocation/cr/{ca}`) — it returns the whole revoked list so the client checks locally and never reveals which certificate it is verifying. Do not "optimize" this into a per-serial lookup.

## What this file does NOT cover

Silence here is not permission — it means nobody has written the rules yet. Say so rather than inferring.

- **`did:pki` resolution** (`pki-resolver.ts`, `trust-*.ts`, `crl-*.ts`) — governed by `did-pki-spec` and the trust-store contract in `@attestto/trust`. The rules above are `did:sns`-specific except Rule 0, the language rules, and the workflow rules, which apply repo-wide.
- **The CR Firma Digital revocation endpoint** beyond the one don't-miss rule below.
- **The registrar / on-chain write path** — it lives in another repo. This repo only reads.
- **`@attestto/did-sns-resolver`**, the published standalone driver — a separate repo with its own rules. Changes here do not propagate there.
