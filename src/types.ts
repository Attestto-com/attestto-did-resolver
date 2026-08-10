/** Parsed components of a did:pki identifier */
export interface ParsedDid {
  method: 'pki';
  countryCode: string;
  caPath: string[];
  generation?: string;
}

/** Certificate metadata from attestto-trust manifest */
export interface CertificateEntry {
  file: string;
  sha256: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  role: 'root' | 'intermediate';
  /** Organization (O) field from Subject DN — optional, extracted from PEM if not in manifest */
  organization?: string;
  /** Common Name (CN) field from Subject DN — optional, extracted from PEM if not in manifest */
  commonName?: string;
}

/** Country manifest from attestto-trust */
export interface CountryManifest {
  country: string;
  generatedAt: string;
  count: number;
  certificates: CertificateEntry[];
}

/** Registry entry — a cert mapped to its DID path */
export interface RegistryEntry {
  did: string;
  countryCode: string;
  caPath: string[];
  cert: CertificateEntry;
  pemPath: string;
  level: 'root' | 'policy' | 'issuing';
  parentDid?: string;
  rootDid: string;
  childDids?: string[];
}

/** W3C DID Document verification method */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: JsonWebKey & { 'x5t#S256'?: string };
}

/** W3C DID Document service endpoint */
export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
}

/** Generation metadata in pkiMetadata */
export interface GenerationMeta {
  keyId: string;
  notBefore: string;
  notAfter: string;
  serialNumber: string;
  fingerprint: string;
  fingerprintAlgorithm: 'sha-256';
  /**
   * Validity-window state. `revoked` is declared because a revocation-aware
   * build should be able to report it — but NOTHING in this resolver produces
   * it today, which is why `revocationChecked` sits beside it.
   */
  status: 'active' | 'expired' | 'not-yet-valid' | 'unknown' | 'revoked';
  /**
   * Whether this resolver checked a revocation source for this certificate.
   *
   * Always false today, and stated rather than implied. `did:pki` consults no
   * CRL or OCSP responder for CA certificates: the CRL service this process
   * runs covers `sinpe-persona-fisica` / `sinpe-persona-juridica`, which are
   * END-ENTITY lists — the certificates those CAs issue — not the CAs
   * themselves. Checking a CA against its own subscribers' list would be a
   * control that looks more convincing and covers less.
   *
   * A consumer that requires revocation assurance must treat
   * `revocationChecked: false` as "unknown", never as "good". Without this
   * field the two are indistinguishable, which is what made
   * attestto-verify's revocation branch vacuous.
   */
  revocationChecked: boolean;
}

/** pkiMetadata extension */
export interface PkiMetadata {
  country: string;
  countryName: string;
  hierarchy: string;
  administrator: string;
  supervisor?: string;
  level: 'root' | 'policy' | 'issuing' | 'timestamping';
  parentDid?: string;
  rootDid: string;
  childDids?: string[];
  endEntityHints?: Record<string, string>;
  generations: GenerationMeta[];
}

/** W3C DID Document */
export interface DidDocument {
  '@context': string[];
  id: string;
  controller: string;
  alsoKnownAs?: string[];
  verificationMethod: VerificationMethod[];
  assertionMethod: string[];
  service?: ServiceEndpoint[];
  pkiMetadata: PkiMetadata;
}

/**
 * W3C DID Document Metadata.
 *
 * Every property is OPTIONAL per DID Core — and this mattered. `created`,
 * `updated` and `versionId` were declared required, so the error path had to
 * supply them and filled in `''`. But `created`/`updated` are XMLSchema
 * dateTime, and `""` is not a value of that type, so every did:pki failure
 * shipped an invalid resolution result — produced BY the type, to satisfy the
 * type. On a failure there is no document, so there is no metadata about one:
 * the correct value is `{}`.
 */
export interface DidDocumentMetadata {
  created?: string;
  updated?: string;
  deactivated?: boolean;
  nextUpdate?: string;
  versionId?: string;
}

/**
 * W3C DID Resolution Metadata.
 *
 * `errorMessage` is the DID Resolution property. This type declared `message`,
 * which is why `did:pki` emitted a field no conforming client reads while
 * `did:sns` — on the same server — emitted the right one: the two methods
 * disagreed because the TYPE let one of them be wrong.
 *
 * `contentType` describes the returned representation, so it is optional: on a
 * failure `didDocument` is null and there is nothing to describe. It was
 * required, so every error result declared a representation that did not
 * exist — and declared `application/did+json` while the server wrote
 * `application/did+ld+json` in the header.
 */
export interface DidResolutionMetadata {
  contentType?: string;
  error?: string;
  errorMessage?: string;
  /** Resolution wall time in ms, reported by the sns resolver. */
  duration?: number;
  /** Set when a transient failure invites an immediate retry. */
  retriable?: boolean;
  /** did:sns on-chain metadata (owner, network, DID metadata flags). */
  snsMetadata?: Record<string, unknown>;
}

/** W3C DID Resolution Result */
export interface DidResolutionResult {
  '@context': string;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
  didResolutionMetadata: DidResolutionMetadata;
}

/** Country metadata for building pkiMetadata */
export interface CountryConfig {
  countryCode: string;
  countryName: string;
  hierarchy: string;
  administrator: string;
  supervisor?: string;
  endEntityHints?: Record<string, Record<string, string>>;
}
