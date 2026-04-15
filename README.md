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
GET /health                    → Health check
```

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
| `SOLANA_RPC_URL` | Solana mainnet public | Custom Solana RPC endpoint (for did:sns) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

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
