# attestto-did-resolver

Unified [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver) driver for Attestto DID methods. Resolves `did:pki` and `did:sns` identifiers to W3C DID Documents.

Part of the [Attestto](https://attestto.org) decentralized identity infrastructure.

## Supported methods

| Method | Description | Spec |
|---|---|---|
| `did:pki` | National PKI bridge — maps X.509 CA hierarchies to DID Documents | [did:pki spec](https://spec.attestto.com/did-pki) |
| `did:sns` | Solana Name Service — resolves `.sol` domain names to DID Documents | [did:sns spec](https://spec.attestto.com/did-sns) |

## API

Conforms to the [DIF Universal Resolver HTTP API](https://github.com/decentralized-identity/universal-resolver/blob/main/docs/driver-development.md):

```
GET /1.0/identifiers/{did}    → W3C DID Resolution Result
GET /1.0/identifiers          → List resolvable did:pki DIDs
GET /1.0/properties            → Driver metadata (DIF convention)
GET /revocation/cr/{ca}        → CR Firma Digital (SINPE) CRL revocation status (JSON, CORS)
GET /health                    → Health check
```

### Revocation endpoint (`GET /revocation/cr/{ca}`)

Lets a browser (e.g. `verify.attestto.com`) learn the revocation status of Costa Rica
CR Firma Digital (SINPE) certificates without fetching the CRL directly — the BCCR CRLs
are plain HTTP with no CORS, so browsers are blocked by both mixed-content and CORS. The
resolver fetches the CRLs server-side, verifies each CRL signature against the CA cert it
already bundles in the trust store, caches the parsed result in memory, and serves it as
CORS-enabled JSON.

`{ca}` is one of `sinpe-persona-fisica` or `sinpe-persona-juridica`. Both current-era CRLs
(`v2(2)` and `v2(3)`) are fetched and their revoked serials merged; the earliest
`nextUpdate` is reported.

**Privacy:** the endpoint takes no certificate serial. It returns the entire revoked list
so the client checks locally and never reveals which certificate it is verifying.

```bash
curl https://resolver.attestto.com/revocation/cr/sinpe-persona-fisica
```

```json
{
  "ca": "sinpe-persona-fisica",
  "issuer": "serialNumber=CPJ-4-000-004017, C=CR, O=BANCO CENTRAL DE COSTA RICA, ...",
  "thisUpdate": "2026-07-21T11:40:06.000Z",
  "nextUpdate": "2026-07-29T00:00:06.000Z",
  "stale": false,
  "signatureVerified": true,
  "revokedSerials": ["14000f93bf...", "..."]
}
```

`signatureVerified` is `true` only when every merged CRL verifies against a bundled CA
cert. It is `false` if a CRL is signed by a CA generation not present in the trust store,
or if an upstream CRL fetch fails (the data is still returned). On total upstream failure
the endpoint returns `502 { "error", "ca", "message" }`. CRL parsing and signature
verification use the built-in `node:crypto` library — no new dependencies.

### Example

```bash
# Resolve a Costa Rica root CA
curl https://resolver.attestto.com/1.0/identifiers/did:pki:cr:raiz-nacional

# Resolve a Solana domain
curl https://resolver.attestto.com/1.0/identifiers/did:sns:attestto
```

Response follows the [W3C DID Resolution](https://www.w3.org/TR/did-core/#did-resolution) format:

```json
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    "id": "did:pki:cr:raiz-nacional",
    "controller": "did:pki:cr:raiz-nacional",
    "verificationMethod": [...],
    "assertionMethod": [...],
    "pkiMetadata": {
      "country": "cr",
      "countryName": "Costa Rica",
      "hierarchy": "SINPE",
      "level": "root",
      ...
    }
  },
  "didDocumentMetadata": { ... },
  "didResolutionMetadata": { "contentType": "application/did+ld+json" }
}
```

## Run locally

```bash
npm install
npm run dev
# Listening on http://localhost:8080
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `TRUST_STORE_PATH` | `./trust-store/countries` | Path to [attestto-trust](https://github.com/Attestto-com/attestto-trust) country manifests (for did:pki) |
| `REFRESH_SECRET` | *(unset → `/admin/refresh` returns 503)* | Bearer token required by `POST /admin/refresh`. Set as a Fly secret; mirror the same value into the attestto-trust GitHub Actions secret `RESOLVER_REFRESH_SECRET`. |
| `REFRESH_INTERVAL_MS` | `21600000` (6h) | Interval for the scheduled npm pull of `@attestto/trust`. |
| `REFRESH_FLOOR_FRACTION` | `0.9` | A refresh is accepted only if its DID count is ≥ this fraction of the current count. |
| `REFRESH_DEBOUNCE_MS` | `30000` | Coalesce refreshes triggered within this window. |
| `SOLANA_RPC_URL` | Solana mainnet public | Custom Solana RPC endpoint (for did:sns) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

### Auto-refresh

The resolver loads the baked `trust-store/` snapshot at boot, then pulls the latest
`@attestto/trust` from npm shortly after startup and every `REFRESH_INTERVAL_MS`. A merge to
`main` in attestto-trust also triggers an immediate refresh via `POST /admin/refresh`
(authenticated with `REFRESH_SECRET`, body `{"source":"main"}`). A fetch that fails or falls
below the sanity floor leaves the current data untouched. `GET /health` reports the live
`trust.source`, `trust.trustVersion`, `trust.didCount`, and `trust.lastRefreshAt`.

## Deploy

Deploys to [Fly.io](https://fly.io) via Docker:

```bash
fly deploy
```

The Docker image bundles the trust store from `trust-store/` and runs as a non-root `node` user with health checks.

## Architecture

```
Request → /1.0/identifiers/{did}
  ├── did:pki:* → DidPkiResolver (X.509 → DID Document)
  │     └── reads attestto-trust country manifests + PEM certs
  └── did:sns:* → DidSnsResolver (Solana Name Service → DID Document)
        └── queries Solana mainnet via @solana/web3.js
```

The trust store for `did:pki` comes from [`attestto-trust`](https://github.com/Attestto-com/attestto-trust), which catalogs national PKI hierarchies with X.509 certificates and manifests.

## Ecosystem

| Package | Role |
|---|---|
| [`attestto-trust`](https://github.com/Attestto-com/attestto-trust) | PKI trust store — country CA manifests + certs |
| [`@attestto/verify`](https://www.npmjs.com/package/@attestto/verify) | Document verification Web Components |
| [`@attestto/login`](https://www.npmjs.com/package/@attestto/login) | DID login Web Component |

## License

Apache 2.0
