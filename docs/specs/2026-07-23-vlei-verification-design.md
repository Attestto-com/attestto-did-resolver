# vLEI Credential Verification — Design (ATT-1069, GLEIF phase 2)

**Date:** 2026-07-23
**Ticket:** ATT-1069 (design: ATT-1061). Depends on phase-1 mirror ATT-1068.
**Repo:** attestto-did-resolver (verification code). Verifies against the phase-1 pinned GLEIF anchor in attestto-trust (`anchors/gleif-vlei/`).

## Goal

Given a presented vLEI credential (Legal Entity vLEI, OOR, or ECR), cryptographically verify it chains to GLEIF's root of trust and report a clean verdict — issuer, holder, role, validity, revocation. Expose it as a resolver API for Attestto's own products and third-party developers.

## Background (from the 2026-07-23 research spike)

- A vLEI is an **ACDC** (Authentic Chained Data Container). Verification walks the chain **Legal Entity <- QVI <- GEDA <- GLEIF Root**, with ~13 checks per hop: SAID integrity, issuer **KEL** (Key Event Log) key-state replay, signature, schema-SAID allowlist, **TEL** (Transaction Event Log) non-revocation, edge continuity, LEI consistency, GEDA delegation, pinned-root anchoring, then EGF business rules.
- **OOR** = Official Organizational Role (registry-backed, ISO 5009 code, IAL2 proofing). **ECR** = Engagement Context Role (entity-defined, lighter proofing).
- **Pivotal constraint:** no mature in-browser/TypeScript KERI-ACDC verifier exists. `signify-ts` only signs (needs a KERIA agent). The real verifiers are Python: `keripy` and GLEIF's `vlei-verifier` (needs a KERI witness network). No cloud SaaS verify endpoint.
- Phase-1 pinned both **GLEIF Root** `EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2` and **GEDA** `EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS` (delegated inception whose delegator is the Root).

## Approach — phased: reuse then build

- **Phase 2a — reuse GLEIF's verifier (ship fast).** Self-host GLEIF's `vlei-verifier` (Python) + a minimal KERI witness setup as a service alongside the resolver. The Node resolver exposes the API, forwards presentations to the verifier, and applies our own independent pinned-anchor gate on top. Fast, and it uses GLEIF's own blessed crypto.
- **Phase 2b — build native (later).** Replace the Python sidecar with a native TypeScript KEL/ACDC verifier so the lean Node resolver verifies in-process against the pin — which also unlocks a **client-side browser widget** for verify.attestto.com (matching the national-PKI mirror-and-pin model). Out of scope for the first implementation; noted so 2a's boundaries stay clean.

## Architecture (phase 2a)

```
   client / dev
        | POST /vlei/verify  (ACDC/CESR presentation)
        v
  attestto-did-resolver (Node)                 [this repo]
    src/keri/
      vlei-endpoint.ts   -- request handling, verdict shaping
      vlei-verifier-client.ts -- async PUT presentation -> poll authorizations
      anchor-gate.ts     -- INDEPENDENT check vs pinned GLEIF Root+GEDA + QVI allowlist
      did-webs.ts        -- did:webs resolution (fetch did.json + keri.cesr, replay KEL)
        |
        v  (localhost / private network)
  GLEIF vlei-verifier (Python) + KERI witnesses   [self-hosted service, security workstream]
```

- `POST /vlei/verify` is routed in `server.ts` by path, alongside the existing `did:pki` / `did:sns` / `/revocation` routes. It is async (the verifier is poll-based), matching the existing `did:sns` async pattern.
- **did method:** consume **did:webs** (not did:keri). did:webs publishes `did.json` + `keri.cesr` (the KEL) at an HTTPS URL that our resolver fetches then replays/verifies — the same fetch shape the resolver already uses. did:keri is accepted only as a bring-your-own-CESR input into the same verify core.

## The independent pinned-anchor gate (our value-add)

We do NOT blindly trust the vlei-verifier's own root configuration. After the verifier returns its cryptographic result, `anchor-gate.ts` independently confirms:
1. the credential chain roots at OUR pinned **GLEIF Root + GEDA** (`anchors/gleif-vlei/root-aid.json`), and
2. the issuing **QVI's LEI is in our allowlist** (`anchors/gleif-vlei/qvis.json`).

This is the same principle as verifying national PKI against our own pinned roots: GLEIF is the source of truth, and we enforce it independently. The `RefreshManager` (ATT-1063) is extended to load `anchors/gleif-vlei/` (Root, GEDA, QVI list) via the existing npm-tarball atomic-swap path, so the gate auto-updates when the anchor changes.

## API

Request: `POST /vlei/verify`, body = the presented credential (ACDC in CESR, or a did:webs reference to resolve).

Response:
```json
{
  "valid": true,
  "credentialType": "OOR",
  "issuerQvi": { "lei": "<QVI LEI>", "aid": "<QVI AID>" },
  "holder": { "lei": "<Legal Entity LEI>", "aid": "<holder AID>" },
  "role": "<ISO 5009 code (OOR) or context string (ECR); absent for LE>",
  "validAt": "<ISO timestamp>",
  "revoked": false,
  "reason": "<human-readable, on failure>"
}
```

## Revocation & freshness

The vlei-verifier checks the TEL against live witnesses per request, so revocation is fresh by default. The resolver caches a verdict briefly (mirroring the CRL-snapshot cache already in `crl-revocation.ts`) to bound witness load; cache TTL is short and configurable.

## Error handling

- Verifier unreachable / timeout -> 502 with a clear reason; never a false "valid".
- Credential fails any gate step -> `valid: false` with the failing reason; fail closed.
- Malformed / oversized body -> 4xx (reuse the capped body-read helper from ATT-1063).
- The endpoint never returns "valid" unless BOTH the verifier passed AND our independent anchor gate passed.

## Infrastructure

The `vlei-verifier` + witness stack runs as a self-hosted service (Fly app or container) adjacent to the resolver, owned and operated by the **security / infrastructure workstream**. It is a trust-critical dependency and is treated as such (monitoring, upgrade discipline, its config cross-checked by our independent gate).

## Testing

Node `node:test`, no live network. Captured fixtures under `src/__tests__/fixtures/vlei/`: one valid Legal Entity vLEI, one valid OOR, one valid ECR credential, plus tampered variants (bad signature, wrong root, revoked, unknown QVI). The vlei-verifier client is mocked; the anchor gate runs against the real pinned `anchors/gleif-vlei/` fixture. Assert each fixture yields the correct verdict and that a tampered/unknown-root credential fails closed.

## Acceptance

- `POST /vlei/verify` verifies LE + OOR + ECR credentials end to end, returns the verdict shape above, and fails closed on any tampered/unknown-root/revoked input.
- The independent gate enforces the phase-1 pinned Root+GEDA + QVI allowlist.
- Fixtures cover valid + tampered for all three types with no live network in tests.
- Reviewed by Eduardo.

## Out of scope (phase 2b and beyond)

- Native TypeScript KEL/ACDC verifier replacing the Python sidecar.
- Client-side browser widget on verify.attestto.com.
- Issuance / acting as a QVI (Attestto is a verifier and mirror, not an issuer).
