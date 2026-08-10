import { createHash, X509Certificate, type KeyObject } from 'node:crypto';
import type {
  RegistryEntry,
  DidDocument,
  DidDocumentMetadata,
  VerificationMethod,
  ServiceEndpoint,
  GenerationMeta,
  PkiMetadata,
} from './types.js';
import { getCountryConfig } from './countries.js';

/**
 * Minimal DER TLV reader — returns the tag, the content offset, and the end
 * offset of one ASN.1 element. Only definite-length encodings occur in SPKI.
 */
function readTLV(
  buf: Buffer,
  off: number,
): { tag: number; contentOff: number; end: number } {
  const tag = buf[off++];
  let len = buf[off++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off++];
  }
  return { tag, contentOff: off, end: off + len };
}

const b64url = (b: Buffer): string => Buffer.from(b).toString('base64url');

/**
 * Build a JWK by hand from a SubjectPublicKeyInfo (SPKI) DER buffer.
 *
 * Node's native `KeyObject.export({ format: 'jwk' })` refuses two key classes
 * that appear in real national PKIs (notably the German HBA/qCA CAs):
 *   - RSA-PSS keys ("Unsupported JWK Key Type") — the key is ordinary RSA, only
 *     the algorithm OID (id-RSASSA-PSS) differs, so we read n/e from the SPKI.
 *   - EC keys on brainpool curves ("Unsupported JWK EC curve") — JWK has no
 *     registered `crv` name, so we emit the OpenSSL curve name (e.g.
 *     "brainpoolP256r1") and the raw x/y coordinates.
 *
 * SPKI = SEQ { SEQ { algOID, params }, BIT STRING subjectPublicKey }.
 */
function spkiToJwk(key: KeyObject): JsonWebKey {
  const der = key.export({ type: 'spki', format: 'der' }) as Buffer;

  // outer SEQUENCE → AlgorithmIdentifier SEQUENCE → BIT STRING
  const outer = readTLV(der, 0);
  const algId = readTLV(der, outer.contentOff);
  const bitStr = readTLV(der, algId.end);
  // BIT STRING content starts with an "unused bits" byte (always 0 here).
  const spk = der.subarray(bitStr.contentOff + 1, bitStr.end);

  const keyType = key.asymmetricKeyType;

  if (keyType === 'rsa' || keyType === 'rsa-pss') {
    // subjectPublicKey wraps RSAPublicKey ::= SEQ { modulus INTEGER, exponent INTEGER }
    const rsaSeq = readTLV(spk, 0);
    const nTlv = readTLV(spk, rsaSeq.contentOff);
    let n = spk.subarray(nTlv.contentOff, nTlv.end);
    const eTlv = readTLV(spk, nTlv.end);
    const e = spk.subarray(eTlv.contentOff, eTlv.end);
    // INTEGERs are signed → drop a leading 0x00 padding byte from the modulus.
    if (n[0] === 0x00) n = n.subarray(1);
    return { kty: 'RSA', n: b64url(n), e: b64url(e) };
  }

  if (keyType === 'ec') {
    // subjectPublicKey = 0x04 || X || Y (uncompressed point).
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (!curve || spk[0] !== 0x04) {
      throw new Error(`Unsupported EC public key encoding (curve: ${curve ?? 'unknown'})`);
    }
    const coord = spk.subarray(1);
    const half = coord.length / 2;
    return {
      kty: 'EC',
      crv: curve,
      x: b64url(coord.subarray(0, half)),
      y: b64url(coord.subarray(half)),
    };
  }

  throw new Error(`Unsupported key type for JWK export: ${keyType}`);
}

/**
 * Extract a JWK public key from a PEM-encoded X.509 certificate.
 *
 * Uses Node's native JWK export for the common cases and falls back to a
 * hand-rolled SPKI parse for RSA-PSS and brainpool-EC keys that Node refuses
 * to export (see spkiToJwk).
 */
function extractJwk(pem: string): JsonWebKey {
  const x509 = new X509Certificate(pem);
  const key = x509.publicKey;
  try {
    return key.export({ format: 'jwk' }) as JsonWebKey;
  } catch {
    return spkiToJwk(key);
  }
}

/**
 * Compute SHA-256 fingerprint of a PEM certificate (DER bytes).
 */
function computeFingerprint(pem: string): string {
  const x509 = new X509Certificate(pem);
  // x509.fingerprint256 returns colon-separated hex
  return x509.fingerprint256.replace(/:/g, '').toLowerCase();
}

/**
 * Extract X.509 extensions for service endpoints (CRL, OCSP, AIA).
 */
function extractServiceEndpoints(pem: string, did: string): ServiceEndpoint[] {
  const services: ServiceEndpoint[] = [];
  const x509 = new X509Certificate(pem);
  const infoAccess = x509.infoAccess;

  if (infoAccess) {
    // Parse infoAccess — format: "OCSP - URI:http://...\nCA Issuers - URI:http://..."
    const lines = typeof infoAccess === 'string'
      ? infoAccess.split('\n')
      : Object.entries(infoAccess).flatMap(([key, vals]) =>
          (vals as string[]).map(v => `${key}:${v}`)
        );

    for (const line of lines) {
      const lineStr = String(line);
      if (lineStr.includes('OCSP')) {
        const uri = lineStr.match(/URI:(https?:\/\/[^\s,]+)/)?.[1];
        if (uri) {
          services.push({
            id: `${did}#ocsp`,
            type: 'OCSPResponder',
            serviceEndpoint: uri,
          });
        }
      }
    }
  }

  return services;
}

/**
 * Where a certificate sits in its own validity window.
 *
 * This deliberately CANNOT return `'revoked'`. Nothing in `did:pki` resolution
 * consults a revocation source, and a status the resolver never determines must
 * not be a value it can emit — `attestto-verify` branches over
 * `'active' | 'revoked' | 'expired'`, and that middle branch has never been
 * reachable. Narrowing the return type is what stops a future edit from
 * quietly reintroducing an unchecked claim.
 *
 * Two changes from the previous version:
 *
 *   - a certificate whose `notBefore` is in the future returned `'active'`,
 *     with a comment conceding it was "not yet valid but still active in
 *     registry". A CA that cannot yet sign is not in service, and a verifier
 *     had no way to tell it from one that is.
 *   - an unparseable date fell through to `'active'`. Every comparison against
 *     an Invalid Date is false, so the guard chain simply missed — and the one
 *     certificate whose dates cannot be read is the one that must never read
 *     as in-service.
 *
 * `now` is a parameter so the result is a function of its inputs.
 */
export type GenerationStatus = 'active' | 'expired' | 'not-yet-valid' | 'unknown';

export function getGenerationStatus(
  validFrom: string,
  validTo: string,
  now: Date = new Date()
): GenerationStatus {
  const notBefore = new Date(validFrom);
  const notAfter = new Date(validTo);

  if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) return 'unknown';

  if (now.getTime() > notAfter.getTime()) return 'expired';
  if (now.getTime() < notBefore.getTime()) return 'not-yet-valid';
  return 'active';
}

/**
 * Build a W3C DID Document from registry entries + PEM data.
 *
 * @param entries - All generations for this DID (may be 1+)
 * @param pemContents - Map of entry file → PEM string
 */
export function buildDidDocument(
  entries: RegistryEntry[],
  pemContents: Map<string, string>,
): { document: DidDocument; metadata: DidDocumentMetadata } {
  if (entries.length === 0) {
    throw new Error('No entries provided');
  }

  const primary = entries[0];
  const did = primary.did;
  const cc = primary.countryCode;
  const config = getCountryConfig(cc);

  // Build verification methods + generation metadata
  const verificationMethods: VerificationMethod[] = [];
  const assertionMethods: string[] = [];
  const generations: GenerationMeta[] = [];
  const allServices: ServiceEndpoint[] = [];

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const pem = pemContents.get(entry.cert.file);
    if (!pem) continue;

    const year = new Date(entry.cert.validFrom).getFullYear();
    const keyId = entries.length > 1 ? `#key-${year}` : '#key-1';
    const vmId = `${did}${keyId}`;

    const jwk = extractJwk(pem);
    const sha256Fingerprint = computeFingerprint(pem);

    verificationMethods.push({
      id: vmId,
      type: 'JsonWebKey2020',
      controller: did,
      // RFC 7517 §4.9 / RFC 7515 §4.1.8: the SHA-256 certificate thumbprint is
      // `x5t#S256`, base64url-encoded. Derived from the same DER as `fingerprint`
      // below so the two representations always agree (see did:pki spec §5).
      publicKeyJwk: { ...jwk, 'x5t#S256': Buffer.from(sha256Fingerprint, 'hex').toString('base64url') },
    });

    assertionMethods.push(vmId);

    const status = getGenerationStatus(entry.cert.validFrom, entry.cert.validTo);

    generations.push({
      keyId,
      notBefore: entry.cert.validFrom,
      notAfter: entry.cert.validTo,
      serialNumber: entry.cert.serialNumber,
      fingerprint: sha256Fingerprint,
      fingerprintAlgorithm: 'sha-256',
      status,
      // Stated, not implied. did:pki consults no revocation source for CA
      // certificates, so a consumer must read this as "unknown" rather than
      // "good" — see the field's doc comment for why the CRL this process
      // already runs is the wrong list.
      revocationChecked: false,
    });

    // Extract services from first generation only (they're usually the same)
    if (i === 0) {
      allServices.push(...extractServiceEndpoints(pem, did));
    }
  }

  // Controller: parent DID for non-root, self for root
  const controller = primary.level === 'root'
    ? did
    : (primary.parentDid ?? did);

  // Determine endEntityHints (only for issuing CAs)
  let endEntityHints: Record<string, string> | undefined;
  if (primary.level === 'issuing' && config.endEntityHints) {
    // Match by last path segment (e.g., "persona-fisica")
    const lastSegment = primary.caPath[primary.caPath.length - 1];
    endEntityHints = config.endEntityHints[lastSegment];
  }

  const pkiMetadata: PkiMetadata = {
    country: config.countryCode,
    countryName: config.countryName,
    hierarchy: config.hierarchy,
    administrator: config.administrator,
    supervisor: config.supervisor,
    level: primary.level,
    parentDid: primary.parentDid,
    rootDid: primary.rootDid,
    childDids: primary.childDids,
    endEntityHints,
    generations,
  };

  const document: DidDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
      'https://spec.attestto.com/v1/pki.jsonld',
    ],
    id: did,
    controller,
    verificationMethod: verificationMethods,
    assertionMethod: assertionMethods,
    pkiMetadata,
  };

  if (allServices.length > 0) {
    document.service = allServices;
  }

  // Build metadata
  const allDates = entries.map(e => new Date(e.cert.validFrom).getTime());
  const created = new Date(Math.min(...allDates)).toISOString();
  const updated = new Date(Math.max(...allDates)).toISOString();

  const allNotAfter = entries.map(e => new Date(e.cert.validTo).getTime());
  const nextUpdate = new Date(Math.min(...allNotAfter)).toISOString();

  // A DID is deactivated when every generation has EXPIRED. `not-yet-valid` is
  // the opposite of deactivated, and `unknown` is an absence of information —
  // neither may be read as retirement. `revoked` stays in the test because a
  // future revocation-aware build should count it, but nothing emits it today.
  const allDeactivated =
    generations.length > 0 && generations.every(g => g.status === 'expired' || g.status === 'revoked');

  // versionId = SHA-256 of concatenated fingerprints
  const fingerprintsConcat = generations.map(g => g.fingerprint).sort().join('');
  const versionId = createHash('sha256').update(fingerprintsConcat).digest('hex');

  const metadata: DidDocumentMetadata = {
    created,
    updated,
    versionId,
    nextUpdate,
  };

  if (allDeactivated) {
    metadata.deactivated = true;
  }

  return { document, metadata };
}
