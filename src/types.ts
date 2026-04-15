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
  publicKeyJwk: JsonWebKey & { x5t?: string };
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
  fingerprintAlgorithm: 'sha-256' | 'sha-1';
  status: 'active' | 'expired' | 'revoked';
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

/** W3C DID Document Metadata */
export interface DidDocumentMetadata {
  created: string;
  updated: string;
  deactivated?: boolean;
  nextUpdate?: string;
  versionId: string;
}

/** W3C DID Resolution Result */
export interface DidResolutionResult {
  '@context': string;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
  didResolutionMetadata: {
    contentType: string;
    error?: string;
    message?: string;
  };
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
