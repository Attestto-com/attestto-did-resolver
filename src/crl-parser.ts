/**
 * Minimal, dependency-free X.509 CRL (RFC 5280) DER parser + signature verifier.
 *
 * Node's built-in `crypto.X509Certificate` can parse certificates but NOT CRLs,
 * so this module walks the DER structure directly to extract the fields we need
 * (issuer DN, thisUpdate/nextUpdate, revoked serials) and verifies the CRL
 * signature with `crypto.verify` against a bundled CA certificate's public key.
 *
 * It intentionally reuses the repo's existing crypto library (`node:crypto`)
 * rather than adding pkijs / node-forge / @peculiar.
 */

import { X509Certificate, verify } from 'node:crypto';

/** A parsed Certificate Revocation List. */
export interface ParsedCrl {
  /** Issuer Distinguished Name, rendered as a comma-separated RFC 4514-ish string. */
  issuer: string;
  /** thisUpdate as an ISO 8601 string. */
  thisUpdate: string;
  /** nextUpdate as an ISO 8601 string, or null if the CRL omits it. */
  nextUpdate: string | null;
  /** Authority Key Identifier (hex, lowercase, no separators) if the CRL carries the AKI extension. */
  authorityKeyId: string | null;
  /** Revoked certificate serials — lowercase hex, no colons, leading zero byte stripped. */
  revokedSerials: string[];
  /** Byte offset range of the tbsCertList (the signed content). */
  tbsBytes: Buffer;
  /** Raw signature bytes. */
  signature: Buffer;
  /** Signature algorithm OID (dotted string). */
  signatureAlgorithmOid: string;
}

// ── DER primitives ──────────────────────────────────────────────────

interface Tlv {
  tag: number;
  headerStart: number;
  headerEnd: number;
  contentEnd: number;
  len: number;
}

function readTlv(buf: Buffer, pos: number): Tlv {
  if (pos >= buf.length) throw new Error('DER: unexpected end of input');
  const tag = buf[pos];
  let p = pos + 1;
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: unsupported length encoding');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[p++];
  }
  const contentEnd = p + len;
  if (contentEnd > buf.length) throw new Error('DER: length exceeds buffer');
  return { tag, headerStart: pos, headerEnd: p, contentEnd, len };
}

function childrenOf(buf: Buffer, seq: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = seq.headerEnd;
  while (p < seq.contentEnd) {
    const t = readTlv(buf, p);
    out.push(t);
    p = t.contentEnd;
  }
  return out;
}

const OID_NAMES: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber',
};

// AuthorityKeyIdentifier extension OID
const OID_AKI = '2.5.29.35';

function decodeOid(buf: Buffer, t: Tlv): string {
  const b = buf.subarray(t.headerEnd, t.contentEnd);
  const parts: number[] = [];
  let v = 0;
  let first = true;
  for (const byte of b) {
    v = (v << 7) | (byte & 0x7f);
    if (!(byte & 0x80)) {
      if (first) {
        parts.push(Math.floor(v / 40));
        parts.push(v % 40);
        first = false;
      } else {
        parts.push(v);
      }
      v = 0;
    }
  }
  return parts.join('.');
}

function decodeName(buf: Buffer, name: Tlv): string {
  const rdns: string[] = [];
  for (const rdn of childrenOf(buf, name)) {
    for (const atv of childrenOf(buf, rdn)) {
      const kids = childrenOf(buf, atv);
      if (kids.length < 2) continue;
      const key = OID_NAMES[decodeOid(buf, kids[0])] ?? decodeOid(buf, kids[0]);
      const val = buf.subarray(kids[1].headerEnd, kids[1].contentEnd).toString('utf8');
      rdns.push(`${key}=${val}`);
    }
  }
  return rdns.join(', ');
}

const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;

function decodeTime(buf: Buffer, t: Tlv): Date {
  const s = buf.subarray(t.headerEnd, t.contentEnd).toString('ascii');
  let y: number;
  let rest: string;
  if (t.tag === UTC_TIME) {
    // YYMMDDHHMMSSZ
    const yy = parseInt(s.slice(0, 2), 10);
    y = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = s.slice(2);
  } else {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    y = parseInt(s.slice(0, 4), 10);
    rest = s.slice(4);
  }
  const mo = rest.slice(0, 2);
  const d = rest.slice(2, 4);
  const h = rest.slice(4, 6);
  const mi = rest.slice(6, 8);
  const se = rest.slice(8, 10) || '00';
  const date = new Date(`${y.toString().padStart(4, '0')}-${mo}-${d}T${h}:${mi}:${se}Z`);
  if (Number.isNaN(date.getTime())) throw new Error(`CRL: unparseable time "${s}"`);
  return date;
}

function serialHex(buf: Buffer, intTlv: Tlv): string {
  let hex = buf.subarray(intTlv.headerEnd, intTlv.contentEnd).toString('hex');
  // Strip a single leading zero byte (sign padding) but keep at least one byte.
  if (hex.length > 2 && hex.startsWith('00')) hex = hex.slice(2);
  return hex.toLowerCase();
}

// ── CRL structure ───────────────────────────────────────────────────
//
// CertificateList ::= SEQUENCE {
//   tbsCertList          TBSCertList,
//   signatureAlgorithm   AlgorithmIdentifier,
//   signatureValue       BIT STRING }
//
// TBSCertList ::= SEQUENCE {
//   version              Version OPTIONAL,
//   signature            AlgorithmIdentifier,
//   issuer               Name,
//   thisUpdate           Time,
//   nextUpdate           Time OPTIONAL,
//   revokedCertificates  SEQUENCE OF SEQUENCE { userCertificate INTEGER, ... } OPTIONAL,
//   crlExtensions        [0] EXPLICIT Extensions OPTIONAL }

const SEQUENCE = 0x30;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const OID_TAG = 0x06;
const CONTEXT_0 = 0xa0;

function extractAki(buf: Buffer, extensions: Tlv): string | null {
  // extensions is [0] EXPLICIT wrapping a SEQUENCE OF Extension
  const kids = childrenOf(buf, extensions);
  const extSeq = kids.find((k) => k.tag === SEQUENCE);
  if (!extSeq) return null;
  for (const ext of childrenOf(buf, extSeq)) {
    const parts = childrenOf(buf, ext);
    const oidPart = parts.find((p) => p.tag === OID_TAG);
    if (!oidPart || decodeOid(buf, oidPart) !== OID_AKI) continue;
    const octet = parts.find((p) => p.tag === OCTET_STRING);
    if (!octet) return null;
    // The OCTET STRING wraps a SEQUENCE { [0] keyIdentifier, ... }
    const inner = readTlv(buf, octet.headerEnd);
    for (const field of childrenOf(buf, inner)) {
      // keyIdentifier is [0] IMPLICIT OCTET STRING → context tag 0x80
      if (field.tag === 0x80) {
        return buf.subarray(field.headerEnd, field.contentEnd).toString('hex').toLowerCase();
      }
    }
    return null;
  }
  return null;
}

/**
 * Parse a DER-encoded CRL. Throws on malformed input.
 */
export function parseCrl(der: Buffer): ParsedCrl {
  const outer = readTlv(der, 0);
  if (outer.tag !== SEQUENCE) throw new Error('CRL: expected outer SEQUENCE');

  const [tbs, sigAlg, sigBits] = childrenOf(der, outer);
  if (!tbs || !sigAlg || !sigBits) throw new Error('CRL: malformed CertificateList');

  // The signed content is the full tbsCertList including its own header.
  const tbsBytes = der.subarray(tbs.headerStart, tbs.contentEnd);

  // signatureValue BIT STRING: first content byte is "unused bits" count (0).
  const signature = der.subarray(sigBits.headerEnd + 1, sigBits.contentEnd);

  const sigAlgKids = childrenOf(der, sigAlg);
  const sigOidTlv = sigAlgKids.find((k) => k.tag === OID_TAG);
  const signatureAlgorithmOid = sigOidTlv ? decodeOid(der, sigOidTlv) : '';

  const tk = childrenOf(der, tbs);
  let i = 0;
  if (tk[i] && tk[i].tag === INTEGER) i++; // optional version
  i++; // signature AlgorithmIdentifier (inside TBS)
  const issuerTlv = tk[i++];
  const thisUpdateTlv = tk[i++];

  let nextUpdate: string | null = null;
  if (tk[i] && (tk[i].tag === UTC_TIME || tk[i].tag === GENERALIZED_TIME)) {
    nextUpdate = decodeTime(der, tk[i++]).toISOString();
  }

  const revokedSerials: string[] = [];
  if (tk[i] && tk[i].tag === SEQUENCE) {
    const revokedSeq = tk[i++];
    for (const entry of childrenOf(der, revokedSeq)) {
      const fields = childrenOf(der, entry);
      const serialTlv = fields.find((f) => f.tag === INTEGER);
      if (serialTlv) revokedSerials.push(serialHex(der, serialTlv));
    }
  }

  let authorityKeyId: string | null = null;
  if (tk[i] && tk[i].tag === CONTEXT_0) {
    authorityKeyId = extractAki(der, tk[i]);
  }

  return {
    issuer: decodeName(der, issuerTlv),
    thisUpdate: decodeTime(der, thisUpdateTlv).toISOString(),
    nextUpdate,
    authorityKeyId,
    revokedSerials,
    tbsBytes,
    signature,
    signatureAlgorithmOid,
  };
}

// Signature-algorithm OID → Node hash name.
const SIG_ALG_HASH: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': 'sha384', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13': 'sha512', // sha512WithRSAEncryption
  '1.2.840.113549.1.1.5': 'sha1', // sha1WithRSAEncryption
  '1.2.840.10045.4.3.2': 'sha256', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': 'sha384', // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4': 'sha512', // ecdsa-with-SHA512
};

/**
 * Verify a parsed CRL's signature against a candidate CA certificate (PEM).
 * Returns true only if the CA's public key validates the CRL signature.
 * Never throws — a verification failure or unsupported algorithm returns false.
 */
export function verifyCrlSignature(crl: ParsedCrl, caCertPem: string): boolean {
  try {
    const hash = SIG_ALG_HASH[crl.signatureAlgorithmOid];
    if (!hash) return false;
    const cert = new X509Certificate(caCertPem);
    return verify(hash, crl.tbsBytes, cert.publicKey, crl.signature);
  } catch {
    return false;
  }
}

/**
 * Compute the Subject Key Identifier (hex, lowercase) of a CA certificate,
 * used to match a CRL's Authority Key Identifier to the signing CA.
 * Returns null if the cert has no SKI extension.
 */
export function subjectKeyId(caCertPem: string): string | null {
  try {
    const cert = new X509Certificate(caCertPem);
    // Node exposes the raw cert; parse the SKI extension (2.5.29.14) from DER.
    const der = cert.raw;
    const outer = readTlv(der, 0);
    const [tbs] = childrenOf(der, outer);
    const tk = childrenOf(der, tbs);
    // TBSCertificate: [0] version?, serial, sigAlg, issuer, validity, subject, spki, ..., [3] extensions
    const extWrap = tk.find((t) => t.tag === 0xa3); // [3] EXPLICIT extensions
    if (!extWrap) return null;
    const extSeq = childrenOf(der, extWrap).find((k) => k.tag === SEQUENCE);
    if (!extSeq) return null;
    for (const ext of childrenOf(der, extSeq)) {
      const parts = childrenOf(der, ext);
      const oidPart = parts.find((p) => p.tag === OID_TAG);
      if (!oidPart || decodeOid(der, oidPart) !== '2.5.29.14') continue;
      const octet = parts.find((p) => p.tag === OCTET_STRING);
      if (!octet) return null;
      const inner = readTlv(der, octet.headerEnd); // OCTET STRING wrapping the KeyIdentifier OCTET STRING
      return der.subarray(inner.headerEnd, inner.contentEnd).toString('hex').toLowerCase();
    }
    return null;
  } catch {
    return null;
  }
}
