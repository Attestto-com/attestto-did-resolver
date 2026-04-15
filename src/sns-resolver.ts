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
  did: string
  name: string
  network: string
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

// ── Resolver ─────────────────────────────────────────────────────────────────

export class DidSnsResolver {
  private connectionCache: Map<string, Connection> = new Map()

  /**
   * Resolve a did:sns DID to a W3C DID Resolution Result.
   */
  async resolve(did: string): Promise<DidResolutionResult> {
    const startTime = Date.now()

    try {
      // Step 1: Parse
      const parsed = this.parseDid(did)
      if (!parsed) {
        return this.errorResult('invalidDid', `Cannot parse DID: ${did}`)
      }

      // Step 2: Derive PDA
      const domainParts = parsed.name.split('.')
      if (domainParts.length > 2) {
        return this.errorResult(
          'invalidDid',
          'SNS supports max 2 levels (parent.subdomain)'
        )
      }

      // Step 3: Fetch on-chain
      const rpcUrl = process.env.SOLANA_RPC_URL || NETWORK_ENDPOINTS[parsed.network] || NETWORK_ENDPOINTS.mainnet
      const connection = this.getConnection(rpcUrl)

      const domainData = await this.fetchDomainData(connection, parsed.name)
      if (!domainData) {
        return this.errorResult('notFound', `No did:sns DID found for: ${parsed.did}`)
      }

      // Verify did:sns compliance — domain must have DID metadata or be an Attestto domain
      const isAttesttoCompliant = domainData.didMetadata?.hasMetadata || parsed.name.includes('attestto')
      if (!isAttesttoCompliant) {
        return this.errorResult('notFound', `No did:sns DID found for: ${parsed.did}`)
      }

      // Step 4: Build DID Document
      const didDocument = this.buildDidDocument(parsed, domainData)

      const duration = Date.now() - startTime

      // Include on-chain DID metadata in resolution metadata
      const snsMetadata: Record<string, unknown> = {
        owner: domainData.owner,
        network: parsed.network,
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
   * Parse a did:sns DID string.
   *
   * Formats:
   *   did:sns:alice.attestto          → mainnet, name = alice.attestto
   *   did:sns:devnet:alice.attestto   → devnet, name = alice.attestto
   *   did:sns:alice                   → mainnet, name = alice (root domain)
   */
  private parseDid(did: string): ParsedSnsDid | null {
    const match = did.match(/^did:sns:(?:(mainnet|devnet|testnet):)?([a-zA-Z0-9][\w.-]*)$/)
    if (!match) return null

    const network = match[1] || 'mainnet'
    const name = match[2]

    if (!name || name.length === 0) return null

    return { did, name, network }
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
    connection: Connection,
    name: string
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

    const accountInfo = await connection.getAccountInfo(domainKey)
    if (!accountInfo || accountInfo.data.length < 96) {
      return null
    }

    // SNS NameRegistry header layout:
    // bytes 0-31:  parentName (PublicKey)
    // bytes 32-63: owner (PublicKey)
    // bytes 64-95: class (PublicKey) — zero = unlocked
    const ownerBytes = accountInfo.data.slice(32, 64)
    const owner = new PublicKey(ownerBytes).toBase58()

    let classKey: string | null = null
    const classKeyBytes = accountInfo.data.slice(64, 96)
    const classKeyPub = new PublicKey(classKeyBytes)
    if (!classKeyPub.equals(PublicKey.default)) {
      classKey = classKeyPub.toBase58()
    }

    // Parse DID metadata from data buffer (bytes 96+)
    const didMetadata = this.parseDidMetadata(accountInfo.data)

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

    const isAttestto = parsed.name.includes('attestto') || meta?.hasMetadata
    const services: ServiceEndpoint[] = []

    // LinkedDomains and platform service only for Attestto domains
    if (isAttestto) {
      services.push({
        id: `${did}#sns-domain`,
        type: 'LinkedDomains',
        serviceEndpoint: `https://${parsed.name}.sol`,
      })

      services.push({
        id: `${did}#attestto-platform`,
        type: 'VerifiablePresentationService',
        serviceEndpoint: {
          origins: ['https://app.attestto.com'],
          presentations: `https://api.attestto.com/ssi/my-credentials`,
        },
      })
    }

    // Add DIDComm messaging service if DID metadata is present and active
    if (meta?.hasMetadata && meta.active) {
      services.push({
        id: `${did}#didcomm`,
        type: 'DIDCommMessaging',
        serviceEndpoint: {
          uri: `https://api.attestto.com/didcomm/`,
          accept: ['didcomm/v2'],
          routingKeys: [],
        },
      })
    }

    // Add vault endpoint hash as a service if present
    if (meta?.hasMetadata && meta.vaultEndpointHash && meta.vaultEndpointHash !== '0'.repeat(64)) {
      services.push({
        id: `${did}#vault`,
        type: 'EncryptedVault',
        serviceEndpoint: {
          endpointHash: meta.vaultEndpointHash,
          encryptionScheme: 'Shamir-2-of-2-XOR',
        },
      })
    }

    // Add SAS attestation reference if present (v2)
    if (meta?.hasSas && meta.sasAttestationUid) {
      services.push({
        id: `${did}#sas-attestation`,
        type: 'SasAttestation',
        serviceEndpoint: {
          attestationPda: meta.sasAttestationUid,
          network: parsed.network,
        },
      })
    }

    // Add status list service only for Attestto domains
    if (isAttestto) {
      services.push({
        id: `${did}#status-list`,
        type: 'BitstringStatusList',
        serviceEndpoint: `https://api.attestto.com/api/status/`,
      })
    }

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
