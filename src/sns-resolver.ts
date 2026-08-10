/**
 * Standalone did:sns Resolver for DIF Universal Resolver
 *
 * Pure resolution logic with zero AdonisJS dependencies.
 * Resolves did:sns DIDs to W3C DID Documents by querying Solana Name Service.
 *
 * Resolution algorithm (per did-sns-method-specification.md §4.2):
 * 1. Parse DID → extract sns-name and optional network
 * 2. Hash domain → derive PDA via SNS program
 * 3. Fetch on-chain account → extract owner public key
 * 4. Construct DID Document with verification methods + services
 *
 * @see https://www.w3.org/TR/did-core/
 * @see https://w3c-ccg.github.io/did-resolution/
 */

import { Connection, PublicKey } from '@solana/web3.js'
import { createHash } from 'node:crypto'
import { parseSnsDid, type SnsNetwork } from './sns-parse.js'

// ── SNS Constants ────────────────────────────────────────────────────────────

const SNS_PROGRAM_ID = new PublicKey('namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX')
const SOL_TLD_PARENT = new PublicKey('58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx')
const HASH_PREFIX = 'SPL Name Service'

const NETWORK_ENDPOINTS: Record<string, string> = {
  mainnet: 'https://api.mainnet-beta.solana.com',
  devnet: 'https://api.devnet.solana.com',
  testnet: 'https://api.testnet.solana.com',
}

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
  'https://w3id.org/security/suites/secp256k1-2019/v1',
  'https://w3id.org/security/suites/x25519-2020/v1',
]

// ── DID Metadata (data buffer bytes 96+) ─────────────────────────────────────

/** Magic bytes: ASCII "DID\x01" — identifies a data buffer as DID metadata */
const DID_MAGIC = Buffer.from([0x44, 0x49, 0x44, 0x01])

const DID_FLAGS = {
  ACTIVE: 0x01,
  HAS_SBT: 0x02,
  TIER_3: 0x04,
  HAS_LEI: 0x08,
  HAS_SAS: 0x10,
} as const

interface DidMetadata {
  hasMetadata: boolean
  version: number
  active: boolean
  hasSbt: boolean
  isTier3: boolean
  hasLei: boolean
  hasSas: boolean
  flags: number
  documentHash: string
  eciesPublicKey: string
  vaultEndpointHash: string
  sasAttestationUid: string | null
  sbtMintAddress: string | null
}

// ── Types ────────────────────────────────────────────────────────────────────

interface ParsedSnsDid {
  /** The identifier as the caller wrote it — DID Core: the document `id` is the DID resolved. */
  did: string
  /** Suffix-stripped, selector-removed: what §9.2 step 4 hashes. */
  name: string
  network: SnsNetwork
}

export interface DidDocument {
  '@context': string[]
  'id': string
  'controller': string[]
  'verificationMethod': VerificationMethod[]
  'authentication': string[]
  'assertionMethod': string[]
  'keyAgreement'?: string[]
  'service'?: ServiceEndpoint[]
}

interface VerificationMethod {
  id: string
  type: string
  controller: string
  publicKeyBase58?: string
  publicKeyMultibase?: string
}

interface ServiceEndpoint {
  id: string
  type: string
  serviceEndpoint: string | Record<string, unknown>
}

export interface DidResolutionResult {
  '@context': string
  didDocument: DidDocument | null
  didResolutionMetadata: DidResolutionMetadata
  didDocumentMetadata: DidDocumentMetadata
}

export interface DidResolutionMetadata {
  contentType?: string
  error?: string
  errorMessage?: string
  duration?: number
  snsMetadata?: Record<string, unknown>
}

export interface DidDocumentMetadata {
  created?: string
  updated?: string
  deactivated?: boolean
  versionId?: string
}

// ── Injected dependencies ────────────────────────────────────────────────────

/**
 * Reads a NameRegistry account. Injected so resolution can be exercised without
 * a Solana RPC — the reason this file had zero tests while carrying four spec
 * violations. The default implementation below preserves the previous
 * behaviour exactly for callers that pass nothing.
 */
export interface SnsAccountReader {
  fetchAccount(address: string, network: SnsNetwork): Promise<Buffer | null>
}

export interface DidSnsResolverDeps extends SnsAccountReader {
  /** Injected so `duration` is not wall-clock in tests. */
  now?: () => number
  /**
   * Service endpoints this deployment advertises for the DIDs it operates.
   *
   * Defaults to NONE. The spec is operator-agnostic (§1) and a driver that
   * hardcodes one company's hostnames into every document is asserting a
   * relationship the subject never entered into. An operator opts in; the
   * published driver does not.
   */
  operatorServices?: (did: string, network: SnsNetwork) => ServiceEndpoint[]
}

// ── Resolver ─────────────────────────────────────────────────────────────────

export class DidSnsResolver {
  private connectionCache: Map<string, Connection> = new Map()
  private readonly deps: Required<DidSnsResolverDeps>

  constructor(deps?: DidSnsResolverDeps) {
    this.deps = {
      fetchAccount: deps?.fetchAccount ?? ((address, network) => this.readFromRpc(address, network)),
      now: deps?.now ?? (() => Date.now()),
      operatorServices: deps?.operatorServices ?? (() => []),
    }
  }

  /** The default reader: a live Solana RPC, as before. */
  private async readFromRpc(address: string, network: SnsNetwork): Promise<Buffer | null> {
    const rpcUrl =
      process.env.SOLANA_RPC_URL || NETWORK_ENDPOINTS[network] || NETWORK_ENDPOINTS.mainnet
    const info = await this.getConnection(rpcUrl).getAccountInfo(new PublicKey(address))
    return info ? info.data : null
  }

  /**
   * Resolve a did:sns DID to a W3C DID Resolution Result.
   */
  async resolve(did: string): Promise<DidResolutionResult> {
    const startTime = this.deps.now()

    try {
      // ── §9.2 steps 1-3: parse, strip `.sol`, validate depth ──────────────
      //
      // Delegated to `sns-parse.ts`, which implements §7.1's ABNF, §7.1's
      // reserved network selectors and §9.2's strip-before-depth ordering. It
      // runs BEFORE any account read, so a malformed name can no longer become
      // a PDA lookup — `did:sns:alice.` used to derive a key from an empty
      // label and answer notFound.
      const parsed = parseSnsDid(did)
      if (!parsed.ok) {
        // §9.2's error set is closed (invalidDid / notFound / deactivated /
        // internalError) and names no code for a depth failure, so `tooDeep`
        // maps onto invalidDid rather than inventing a fifth wire value.
        // SOC-177 asks the spec to name one.
        return this.errorResult('invalidDid', parsed.message)
      }
      const { name, network } = parsed.value

      const domainData = await this.fetchDomainData(name, network)
      if (!domainData) {
        return this.errorResult('notFound', `No did:sns DID found for: ${did}`)
      }

      // §9.1: "DID registration requires an on-chain write." §12: "DID
      // registration is not implicit."
      //
      // This used to read `|| name.includes('attestto')`, accepting a SUBSTRING
      // of the name as a substitute for the 0x44494401 write. `attesttofake`,
      // `not-attestto-really` and `x.attestto-evil` all satisfied it, so anyone
      // could register such a `.sol` name with an empty buffer and receive a
      // resolver-blessed document — on the vendor's own brand, which §3.2's
      // Model D warning exists to prevent a verifier from trusting.
      //
      // Registration is the write. There is no name that skips it.
      if (!domainData.didMetadata?.hasMetadata) {
        return this.errorResult('notFound', `No did:sns DID found for: ${did}`)
      }

      // Step 4: Build DID Document
      const didDocument = this.buildDidDocument({ did, name, network }, domainData)

      const duration = this.deps.now() - startTime

      // Include on-chain DID metadata in resolution metadata
      const snsMetadata: Record<string, unknown> = {
        owner: domainData.owner,
        network,
        classKey: domainData.classKey,
      }

      if (domainData.didMetadata) {
        snsMetadata.didMetadata = {
          version: domainData.didMetadata.version,
          active: domainData.didMetadata.active,
          hasSbt: domainData.didMetadata.hasSbt,
          isTier3: domainData.didMetadata.isTier3,
          hasLei: domainData.didMetadata.hasLei,
          hasSas: domainData.didMetadata.hasSas,
          documentHash: domainData.didMetadata.documentHash,
        }
      }

      return {
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument,
        didResolutionMetadata: {
          contentType: 'application/did+ld+json',
          duration,
          snsMetadata,
        },
        didDocumentMetadata: {
          versionId: domainData.owner,
          ...(domainData.didMetadata?.active === false ? { deactivated: true } : {}),
        },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      return this.errorResult('internalError', message)
    }
  }

  /**
   * Hash a domain name for SNS PDA derivation.
   */
  private hashDomainName(name: string): Buffer {
    const input = `${HASH_PREFIX}${name}`
    return createHash('sha256').update(input, 'utf8').digest()
  }

  /**
   * Fetch domain data from Solana Name Service.
   */
  private async fetchDomainData(
    name: string,
    network: SnsNetwork
  ): Promise<{ owner: string; classKey: string | null; didMetadata: DidMetadata | null } | null> {
    const parts = name.split('.')

    let domainKey: PublicKey

    // SNS PDA derivation requires 3 seeds: [hashedName, nameClass, parentKey]
    // nameClass is PublicKey.default (all zeros) for standard domains
    const nameClass = PublicKey.default

    if (parts.length === 1) {
      // Root domain: alice → hash("alice") with parent = SOL_TLD
      const hashedName = this.hashDomainName(parts[0])
      const [key] = PublicKey.findProgramAddressSync(
        [hashedName, nameClass.toBuffer(), SOL_TLD_PARENT.toBuffer()],
        SNS_PROGRAM_ID
      )
      domainKey = key
    } else {
      // Subdomain: alice.attestto → hash("attestto") for parent, then hash("\0alice") with parent key
      const parentHash = this.hashDomainName(parts[1])
      const [parentKey] = PublicKey.findProgramAddressSync(
        [parentHash, nameClass.toBuffer(), SOL_TLD_PARENT.toBuffer()],
        SNS_PROGRAM_ID
      )

      const subHash = this.hashDomainName(`\0${parts[0]}`)
      const [subKey] = PublicKey.findProgramAddressSync(
        [subHash, nameClass.toBuffer(), parentKey.toBuffer()],
        SNS_PROGRAM_ID
      )
      domainKey = subKey
    }

    const data = await this.deps.fetchAccount(domainKey.toBase58(), network)
    if (!data || data.length < 96) {
      return null
    }

    // SNS NameRegistry header layout:
    // bytes 0-31:  parentName (PublicKey)
    // bytes 32-63: owner (PublicKey)
    // bytes 64-95: class (PublicKey) — zero = unlocked
    const ownerBytes = data.slice(32, 64)
    const owner = new PublicKey(ownerBytes).toBase58()

    let classKey: string | null = null
    const classKeyBytes = data.slice(64, 96)
    const classKeyPub = new PublicKey(classKeyBytes)
    if (!classKeyPub.equals(PublicKey.default)) {
      classKey = classKeyPub.toBase58()
    }

    // Parse DID metadata from data buffer (bytes 96+)
    const didMetadata = this.parseDidMetadata(data)

    return { owner, classKey, didMetadata }
  }

  /**
   * Parse DID metadata from account data buffer (bytes 96+).
   * Returns null if no magic bytes found or data too short.
   */
  private parseDidMetadata(accountData: Buffer): DidMetadata | null {
    if (accountData.length <= 96) return null

    const dataBuf = accountData.slice(96)

    // Check magic bytes
    if (dataBuf.length < 4 || !dataBuf.slice(0, 4).equals(DID_MAGIC)) {
      return null
    }

    if (dataBuf.length < 160) return null

    const version = dataBuf[4]
    const flags = dataBuf[5]

    const isV2 = version === 0x02

    // v1: [0-3 magic, 4 ver, 5 flags, 6-37 docHash, 38-70 ecies, 71-102 vaultHash, 103-134 sbtMint]
    // v2: [0-3 magic, 4 ver, 5 flags, 6-37 sasUid,  38-70 ecies, 71-102 vaultHash, 103-134 docHash]
    const ZERO_32 = Buffer.alloc(32)

    const eciesPublicKey = dataBuf.slice(38, 71).toString('hex')
    const vaultEndpointHash = dataBuf.slice(71, 103).toString('hex')

    let documentHash: string
    let sasAttestationUid: string | null = null
    let sbtMintAddress: string | null = null

    if (isV2) {
      const sasBytes = dataBuf.slice(6, 38)
      sasAttestationUid = sasBytes.equals(ZERO_32) ? null : new PublicKey(sasBytes).toBase58()
      documentHash = dataBuf.slice(103, 135).toString('hex')
    } else {
      documentHash = dataBuf.slice(6, 38).toString('hex')
      const sbtBytes = dataBuf.slice(103, 135)
      sbtMintAddress = sbtBytes.equals(ZERO_32) ? null : new PublicKey(sbtBytes).toBase58()
    }

    return {
      hasMetadata: true,
      version,
      active: (flags & DID_FLAGS.ACTIVE) !== 0,
      hasSbt: (flags & DID_FLAGS.HAS_SBT) !== 0,
      isTier3: (flags & DID_FLAGS.TIER_3) !== 0,
      hasLei: (flags & DID_FLAGS.HAS_LEI) !== 0,
      hasSas: (flags & DID_FLAGS.HAS_SAS) !== 0,
      flags,
      documentHash,
      eciesPublicKey,
      vaultEndpointHash,
      sasAttestationUid,
      sbtMintAddress,
    }
  }

  /**
   * Build a W3C DID Document from parsed DID and on-chain data.
   */
  private buildDidDocument(
    parsed: ParsedSnsDid,
    domainData: { owner: string; classKey: string | null; didMetadata: DidMetadata | null }
  ): DidDocument {
    const did = parsed.did
    const ownerKey = domainData.owner
    const meta = domainData.didMetadata

    const verificationMethods: VerificationMethod[] = [
      {
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyBase58: ownerKey,
      },
    ]

    const keyAgreement: string[] = []

    // If on-chain metadata has an ECIES public key, add secp256k1 verification method
    if (meta?.hasMetadata && meta.eciesPublicKey && meta.eciesPublicKey !== '0'.repeat(66)) {
      verificationMethods.push({
        id: `${did}#ecies-key`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: did,
        publicKeyMultibase: `z${meta.eciesPublicKey}`,
      })
      keyAgreement.push(`${did}#ecies-key`)
    }

    // ── §8.6 service endpoints ──────────────────────────────────────────
    //
    // §1: the method is "operator-agnostic — any SNS domain owner … can anchor
    // DIDs under their namespace". §8.4: "Service endpoints point to the
    // tenant's infrastructure (whitelabel)."
    //
    // This block used to attach `api.attestto.com` / `app.attestto.com` VP,
    // DIDComm and status-list endpoints to EVERY document, sourced from nothing
    // on-chain — so resolving an independent operator's DID told every verifier
    // to fetch that subject's presentations and revocation status from a third
    // party they have no relationship with. §12.5 lists exactly that
    // ("repoint the vault / VP / DIDComm service endpoints") as an ATTACKER
    // capability. A public DIF driver performing it by default is worse than an
    // attacker doing it once.
    //
    // Nothing is emitted that the chain did not supply:
    //
    //   - `LinkedDomains https://<name>.sol` was fabricated from the name, and
    //     asserted a hostname in a TLD that does not exist in DNS.
    //     `LinkedDomains` is also not among §8.6's five service types.
    //   - the vault entry carried `EncryptedVault` (§8.6 defines
    //     `EncryptedDataVault`) with the buffer's *hash* where §8.2/§8.4 put a
    //     URL. §10 is explicit that the buffer holds "SHA-256 of vault service
    //     endpoint URL" — a commitment, not an endpoint. A hash cannot be
    //     dereferenced, so there is no conformant value to emit. It stays in
    //     `snsMetadata`, where a consumer that knows the URL can check it.
    //   - `SasAttestation` is not a §8.6 type. The UID is already reported in
    //     `didResolutionMetadata.snsMetadata`, so nothing is lost by dropping
    //     the service entry.
    //
    // An operator that wants its own endpoints advertised configures them; the
    // driver ships neutral. Per Rule 0, a resolver does not invent an endpoint
    // any more than it invents a key.
    const services: ServiceEndpoint[] = this.deps.operatorServices(did, parsed.network)

    const doc: DidDocument = {
      '@context': DID_CONTEXT,
      'id': did,
      'controller': [did],
      'verificationMethod': verificationMethods,
      'authentication': [`${did}#key-1`],
      'assertionMethod': [`${did}#key-1`],
      ...(services.length > 0 ? { service: services } : {}),
    }

    if (keyAgreement.length > 0) {
      doc.keyAgreement = keyAgreement
    }

    return doc
  }

  /**
   * Build an error resolution result.
   */
  private errorResult(error: string, errorMessage: string): DidResolutionResult {
    return {
      '@context': 'https://w3id.org/did-resolution/v1',
      didDocument: null,
      didResolutionMetadata: { error, errorMessage },
      didDocumentMetadata: {},
    }
  }

  /**
   * Get or create a cached Solana connection.
   */
  private getConnection(rpcUrl: string): Connection {
    let conn = this.connectionCache.get(rpcUrl)
    if (!conn) {
      conn = new Connection(rpcUrl, 'confirmed')
      this.connectionCache.set(rpcUrl, conn)
    }
    return conn
  }
}
