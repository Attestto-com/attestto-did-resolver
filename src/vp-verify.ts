/**
 * `POST /1.0/verify` — cryptographic verification of a Verifiable Presentation.
 *
 * SOC-181. `@attestto/id-wallet-adapter` has always posted presentations here
 * (`verify.ts:282`) and this route did not exist, so every response was the
 * 404 handler, `res.ok` was false, `verifySignature` returned false, and
 * `verifyPresentation` could not return `valid: true` for ANY input. Every DID
 * login through `@attestto/login` failed. Failing closed was correct; the
 * defect was that the counterparty half of a written contract was never built,
 * so the safe path was also the only path.
 *
 * ## What this endpoint exists to add
 *
 * The adapter already compares `proof.challenge` / `proof.domain` against what
 * it expected. That check is worth having and is NOT worth trusting on its own,
 * because those two fields are **unsigned metadata**: they sit in the proof
 * object next to the signature, not under it. Anyone holding a captured
 * presentation can rewrite them to whatever a verifier is asking for, and the
 * adapter's local comparison passes.
 *
 * The wallet signs a compact JWS whose PAYLOAD carries the same two values as
 * `nonce` and `aud` (`attestto-creds-extension/src/services/jsonld-vp.ts`,
 * `createChapiVp`). Those are covered by the signature. So the one thing this
 * endpoint must do, and the reason the ticket says a half-implementation is
 * worse than the 404, is bind the challenge and domain to the SIGNED claims —
 * never to the proof's plaintext copies. An endpoint that verified the
 * signature and then compared `proof.challenge` would be exactly as vacuous as
 * the check it was built to backstop, while looking like the fix.
 *
 * The same reasoning applies to the presented document itself. The JWS payload
 * carries `vp`, the presentation as it was at signing time. If we verified the
 * signature and then returned `valid: true` for whatever envelope arrived, a
 * captured proof could be re-served around a different `verifiableCredential`
 * array: the signature still verifies, over a document nobody presented. So
 * the outer envelope is compared, canonically, against the signed copy.
 *
 * ## What it deliberately does not do
 *
 * It answers one question: is this presentation cryptographically bound to the
 * key its proof names, in the holder's own document, over this challenge and
 * this domain. It does not evaluate the credentials inside — issuer trust,
 * revocation and schema are the caller's, and the adapter does them itself.
 * `valid: true` here is not a statement that a credential is good.
 */
import { constants, createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto'
import bs58 from 'bs58'

/** How stale a signed `iat` may be before the presentation is refused. */
const DEFAULT_MAX_AGE_SECONDS = 300

/**
 * Tolerance for a signer whose clock runs ahead of ours.
 *
 * Mirrors the adapter's `FUTURE_SKEW_TOLERANCE_SECONDS`. Without it a wallet a
 * few seconds fast fails every login on a correctly-signed presentation.
 */
const FUTURE_SKEW_TOLERANCE_SECONDS = 60

/** Multicodec prefix for an ed25519 public key, as used in `publicKeyMultibase`. */
const ED25519_PUB_PREFIX = Uint8Array.from([0xed, 0x01])

/**
 * DER prefix for a 32-byte raw ed25519 key in SubjectPublicKeyInfo form.
 *
 * `createPublicKey` takes SPKI or JWK, never raw bytes, and the OKP JWK route
 * would mean base64url-encoding the same bytes to have them decoded again. The
 * prefix is fixed for ed25519 (RFC 8410 §4): SEQUENCE, AlgorithmIdentifier
 * 1.3.101.112, BIT STRING of 32 bytes.
 */
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])

export interface VerifyError {
  code: string
  message: string
}

export interface VerifyPresentationResult {
  valid: boolean
  holder: string | null
  errors: VerifyError[]
}

/** Resolves a DID to its document, or null when it does not resolve. */
export type ResolveDidDocument = (did: string) => Promise<Record<string, unknown> | null>

export interface VerifyPresentationOptions {
  maxAgeSeconds?: number
  /** Injectable clock. Tests need a fixed `now`; nothing else should set it. */
  now?: number
}

type Json = Record<string, unknown>

const isObject = (v: unknown): v is Json =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

const isNonEmptyString = (v: unknown): v is string =>
  typeof v === 'string' && v.trim().length > 0

const err = (code: string, message: string): VerifyPresentationResult['errors'] => [{ code, message }]

const fail = (holder: string | null, code: string, message: string): VerifyPresentationResult => ({
  valid: false,
  holder,
  errors: err(code, message),
})

/**
 * Verify a presentation against an expected challenge and domain.
 *
 * Returns the first failure rather than a list. A presentation is either bound
 * to this verifier's challenge on a key the holder controls or it is not, and
 * enumerating everything else wrong with a rejected presentation tells an
 * attacker which of their guesses got closest.
 */
export async function verifyPresentation(
  body: unknown,
  resolve: ResolveDidDocument,
  options: VerifyPresentationOptions = {},
): Promise<VerifyPresentationResult> {
  const now = options.now ?? Date.now()
  const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS

  if (!isObject(body)) {
    return fail(null, 'invalidRequest', 'Request body must be a JSON object')
  }

  const { verifiablePresentation, expectedChallenge, expectedDomain } = body

  // A blank expectation must never authenticate anything. Were these allowed
  // through, a presentation that also left the field blank would "match" and
  // the binding gate would be a no-op — the caller's misconfiguration silently
  // becoming an authentication bypass. The adapter refuses these locally too;
  // it is refused again here because this endpoint is reachable by callers
  // that are not the adapter.
  if (!isNonEmptyString(expectedChallenge) || !isNonEmptyString(expectedDomain)) {
    return fail(
      null,
      'invalidRequest',
      'expectedChallenge and expectedDomain are required and must be non-empty strings',
    )
  }

  if (!isObject(verifiablePresentation)) {
    return fail(null, 'invalidRequest', 'verifiablePresentation must be a JSON object')
  }

  const vp = verifiablePresentation
  const holder = extractHolder(vp)
  if (!holder) {
    return fail(null, 'noHolder', 'Presentation has no holder DID')
  }

  const proofs = extractProofs(vp)
  if (proofs.length === 0) {
    return fail(holder, 'proofMissing', 'Presentation carries no proof')
  }

  const document = await resolve(holder)
  if (!document) {
    return fail(holder, 'holderUnresolvable', `Could not resolve holder DID: ${holder}`)
  }

  // The document the proofs are checked against, with `proof` removed. Computed
  // once: every proof is a claim about this same envelope.
  const presented = canonicalize(omitProof(vp))

  // EVERY proof must verify, not merely one.
  //
  // The obvious implementation finds a proof that binds the expected challenge
  // and checks that one. Then a presentation carrying a valid proof beside a
  // forged one verifies, and the caller is told `valid: true` about a document
  // it will go on to read whole. A proof array is a set of claims about the
  // same document; one of them being false makes the document untrustworthy,
  // not partly trustworthy. The ticket asks for this case by name.
  for (const proof of proofs) {
    const result = await verifyProof({
      proof,
      holder,
      document,
      presented,
      expectedChallenge,
      expectedDomain,
      now,
      maxAgeSeconds,
    })
    if (result) return { valid: false, holder, errors: [result] }
  }

  return { valid: true, holder, errors: [] }
}

interface ProofContext {
  proof: Json
  holder: string
  document: Json
  presented: string
  expectedChallenge: string
  expectedDomain: string
  now: number
  maxAgeSeconds: number
}

/** Returns an error, or null when the proof is good. */
async function verifyProof(ctx: ProofContext): Promise<VerifyError | null> {
  const { proof, holder, document, presented, expectedChallenge, expectedDomain } = ctx

  const verificationMethod = proof.verificationMethod
  if (!isNonEmptyString(verificationMethod)) {
    return { code: 'proofMalformed', message: 'Proof has no verificationMethod' }
  }

  // A bare DID names a document, not a key, and leaves the verifier to choose
  // one — which is SOC-174's defect on the verifying side. Which key signed is
  // the proof's statement to make.
  const hash = verificationMethod.indexOf('#')
  if (hash < 0 || hash === verificationMethod.length - 1) {
    return {
      code: 'verificationMethodNotAKey',
      message: `verificationMethod has no fragment: ${verificationMethod} — it names a document, not a key`,
    }
  }
  if (verificationMethod.slice(0, hash) !== holder) {
    return {
      code: 'verificationMethodForeign',
      message: `verificationMethod ${verificationMethod} does not belong to holder ${holder}`,
    }
  }

  const jws = proof.jws
  if (!isNonEmptyString(jws)) {
    return { code: 'proofMalformed', message: 'Proof carries no jws' }
  }

  // The proof's own `challenge` / `domain` are unsigned, so they prove nothing
  // on their own. They are still checked, because a presentation whose visible
  // metadata disagrees with what was signed is malformed, and returning
  // `valid: true` for it would leave the caller reading fields we did not
  // verify. The values that DECIDE are the signed ones, below.
  if (proof.challenge !== expectedChallenge) {
    return { code: 'challengeMismatch', message: 'Proof challenge does not match expectedChallenge' }
  }
  if (proof.domain !== expectedDomain) {
    return { code: 'domainMismatch', message: 'Proof domain does not match expectedDomain' }
  }

  // The proof purpose decides WHICH relationship in the document may authorize
  // this key. A presentation proof authenticates the holder, so the key must be
  // listed under `authentication` — being present in `verificationMethod` is
  // not authorization to log in, it is only a place the key is written down.
  const purpose = isNonEmptyString(proof.proofPurpose) ? proof.proofPurpose : 'authentication'
  if (purpose !== 'authentication') {
    return {
      code: 'proofPurposeInvalid',
      message: `Presentation proof purpose must be authentication, got: ${purpose}`,
    }
  }
  if (!relationshipContains(document.authentication, verificationMethod)) {
    return {
      code: 'keyNotAuthorized',
      message: `${verificationMethod} is not listed under authentication in the holder's document`,
    }
  }

  const method = findVerificationMethod(document, verificationMethod, holder)
  if (!method) {
    return {
      code: 'verificationMethodNotFound',
      message: `${verificationMethod} is not present in the holder's DID document`,
    }
  }

  let key: ImportedKey
  try {
    key = importKey(method)
  } catch (error) {
    return {
      code: 'keyUnusable',
      message: `Could not read key material for ${verificationMethod}: ${message(error)}`,
    }
  }

  const parsed = parseCompactJws(jws)
  if ('error' in parsed) return parsed.error

  const { header, payload, signingInput, signature } = parsed

  // Pin the algorithm to the RESOLVED KEY, never to the header.
  //
  // `alg` is attacker-controlled: it travels inside the token being checked.
  // Trusting it is the JWT algorithm-confusion family — `alg: none`, or `HS256`
  // verified with the public key as the HMAC secret, which anyone holding the
  // public document can compute. The key type in the DID document admits
  // exactly one signature scheme, and that is the only one we will run.
  if (!key.algorithms.includes(header.alg)) {
    return {
      code: 'algorithmNotPermitted',
      message: `Proof declares alg ${header.alg}, which the resolved ${key.description} key cannot produce`,
    }
  }

  if (!verifySignature(key, header.alg, signingInput, signature)) {
    return { code: 'signatureInvalid', message: 'Presentation proof signature does not verify' }
  }

  // ── Everything below is checked against SIGNED claims ──────────────
  // Reaching here means the signature is good. It does not yet mean the
  // presentation was made for US: a correctly-signed presentation captured
  // from another site, or from an earlier login on this one, arrives here
  // fully intact.

  if (payload.nonce !== expectedChallenge) {
    return {
      code: 'challengeUnbound',
      message:
        'Signed nonce does not match expectedChallenge — the proof was not made over this challenge (replay)',
    }
  }
  if (!audienceMatches(payload.aud, expectedDomain)) {
    return {
      code: 'domainUnbound',
      message:
        'Signed audience does not match expectedDomain — the proof was made for a different site (cross-origin replay)',
    }
  }
  if (payload.iss !== holder) {
    return {
      code: 'issuerMismatch',
      message: `Signed iss (${String(payload.iss)}) is not the presentation holder (${holder})`,
    }
  }

  // The signature covers the payload's `vp`, not the envelope that arrived. A
  // captured proof re-served around different credentials verifies perfectly
  // and presents a document nobody signed.
  if (!isObject(payload.vp)) {
    return { code: 'signedDocumentMissing', message: 'Signed payload carries no vp' }
  }
  if (canonicalize(omitProof(payload.vp)) !== presented) {
    return {
      code: 'documentAltered',
      message: 'The presented document differs from the one covered by the signature',
    }
  }

  // Freshness, from `iat`, for the same reason the challenge comes from the
  // payload: `proof.created` is unsigned. The adapter enforces its window on
  // that field, so without this check the only freshness gate in the system
  // reads a value the presenter can rewrite.
  const iat = payload.iat
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    return {
      code: 'proofNotFresh',
      message: 'Signed payload has no numeric iat; freshness cannot be established',
    }
  }
  const ageSeconds = ctx.now / 1000 - iat
  if (ageSeconds > ctx.maxAgeSeconds) {
    return { code: 'proofNotFresh', message: `Proof is older than ${ctx.maxAgeSeconds}s (replay)` }
  }
  if (ageSeconds < -FUTURE_SKEW_TOLERANCE_SECONDS) {
    return { code: 'proofNotFresh', message: 'Signed iat is in the future' }
  }
  if (typeof payload.exp === 'number' && ctx.now / 1000 > payload.exp) {
    return { code: 'proofNotFresh', message: 'Proof has expired (exp)' }
  }

  return null
}

// ── Presentation shape ──────────────────────────────────────────────

function extractHolder(vp: Json): string | null {
  const h = vp.holder
  if (typeof h === 'string' && h.startsWith('did:')) return h
  if (isObject(h) && typeof h.id === 'string' && h.id.startsWith('did:')) return h.id
  return null
}

function extractProofs(vp: Json): Json[] {
  const p = vp.proof
  if (Array.isArray(p)) return p.filter(isObject)
  if (isObject(p)) return [p]
  return []
}

function omitProof(vp: Json): Json {
  const { proof: _proof, ...rest } = vp
  return rest
}

/**
 * A stable string for two documents that should be identical.
 *
 * Not JSON-LD canonicalization (URDNA2015): this compares one JSON document
 * against another copy of the same JSON document, where key order is the only
 * thing expected to differ. Semantic equivalence under different `@context`
 * expansions is not the question being asked, and answering it would mean
 * treating documents that expand alike but read differently as the same.
 */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (isObject(value)) {
    const keys = Object.keys(value).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}

function audienceMatches(aud: unknown, expectedDomain: string): boolean {
  if (typeof aud === 'string') return aud === expectedDomain
  if (Array.isArray(aud)) return aud.includes(expectedDomain)
  return false
}

// ── DID document lookup ─────────────────────────────────────────────

/**
 * Whether a verification relationship authorizes this key.
 *
 * Entries may be absolute (`did:sns:x#solana-key`) or relative (`#solana-key`)
 * — `did:sns` documents use the absolute form and other methods use the short
 * one, and both mean the same key.
 */
function relationshipContains(relationship: unknown, verificationMethod: string): boolean {
  if (!Array.isArray(relationship)) return false
  const fragment = verificationMethod.slice(verificationMethod.indexOf('#'))
  return relationship.some((entry) => {
    if (typeof entry === 'string') return entry === verificationMethod || entry === fragment
    // An embedded verification method is authorization in itself (DID Core §5.3).
    if (isObject(entry) && typeof entry.id === 'string') {
      return entry.id === verificationMethod || entry.id === fragment
    }
    return false
  })
}

function findVerificationMethod(document: Json, verificationMethod: string, did: string): Json | null {
  const fragment = verificationMethod.slice(verificationMethod.indexOf('#'))
  const candidates: unknown[] = []
  if (Array.isArray(document.verificationMethod)) candidates.push(...document.verificationMethod)
  if (Array.isArray(document.authentication)) candidates.push(...document.authentication)
  for (const entry of candidates) {
    if (!isObject(entry) || typeof entry.id !== 'string') continue
    if (entry.id === verificationMethod || entry.id === fragment || entry.id === `${did}${fragment}`) {
      return entry
    }
  }
  return null
}

// ── Key material ────────────────────────────────────────────────────

interface ImportedKey {
  key: KeyObject
  /** The signature schemes this key type can produce. Nothing else is run. */
  algorithms: string[]
  description: string
}

function importKey(method: Json): ImportedKey {
  if (isObject(method.publicKeyJwk)) return importJwk(method.publicKeyJwk)
  if (typeof method.publicKeyMultibase === 'string') {
    return importMultibase(method.publicKeyMultibase)
  }
  throw new Error('verification method has neither publicKeyJwk nor publicKeyMultibase')
}

function importJwk(jwk: Json): ImportedKey {
  const kty = jwk.kty
  const crv = jwk.crv

  // A private key in a DID document would be a catastrophic publication, and
  // importing one here would verify happily and hide it. Refuse the shape.
  if ('d' in jwk) throw new Error('JWK contains a private component')

  let algorithms: string[]
  let description: string
  if (kty === 'EC' && crv === 'P-256') {
    algorithms = ['ES256']
    description = 'EC P-256'
  } else if (kty === 'EC' && crv === 'P-384') {
    algorithms = ['ES384']
    description = 'EC P-384'
  } else if (kty === 'OKP' && crv === 'Ed25519') {
    algorithms = ['EdDSA']
    description = 'Ed25519'
  } else if (kty === 'RSA') {
    algorithms = ['RS256', 'PS256']
    description = 'RSA'
  } else {
    throw new Error(`unsupported key type: kty=${String(kty)} crv=${String(crv)}`)
  }

  // `use` and `key_ops`, when present, are the document's own statement about
  // what the key may do. A key published for encryption is not a signing key.
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    throw new Error(`JWK use is ${String(jwk.use)}, not sig`)
  }
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes('verify')) {
    throw new Error('JWK key_ops does not permit verify')
  }

  return { key: createPublicKey({ key: jwk as never, format: 'jwk' }), algorithms, description }
}

/**
 * Read an ed25519 key out of a `publicKeyMultibase` value.
 *
 * The `z` prefix is a CLAIM that what follows is base58btc, and the multicodec
 * prefix is a claim about the key type. Both are checked rather than assumed:
 * `attestto-desktop` currently emits `z` over base64url (SOC-191), and the
 * resolver's own ECIES entry used to be `"z" + hex`. Accepting a mislabelled
 * encoding would mean verifying against bytes that are not the key.
 */
function importMultibase(value: string): ImportedKey {
  if (!value.startsWith('z')) {
    throw new Error(`publicKeyMultibase is not base58btc (expected a leading z): ${value.slice(0, 8)}…`)
  }
  let decoded: Uint8Array
  try {
    decoded = bs58.decode(value.slice(1))
  } catch {
    throw new Error('publicKeyMultibase claims base58btc but does not decode as base58')
  }
  if (decoded[0] !== ED25519_PUB_PREFIX[0] || decoded[1] !== ED25519_PUB_PREFIX[1]) {
    throw new Error(
      `publicKeyMultibase is not an ed25519 key (multicodec 0x${decoded[0]?.toString(16)}${decoded[1]?.toString(16)})`,
    )
  }
  const raw = decoded.subarray(2)
  if (raw.length !== 32) {
    throw new Error(`ed25519 key is ${raw.length} bytes, expected 32`)
  }
  const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length)
  spki.set(ED25519_SPKI_PREFIX, 0)
  spki.set(raw, ED25519_SPKI_PREFIX.length)
  return {
    key: createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' }),
    algorithms: ['EdDSA'],
    description: 'Ed25519',
  }
}

// ── JWS ─────────────────────────────────────────────────────────────

interface ParsedJws {
  header: { alg: string }
  payload: Json
  signingInput: Buffer
  signature: Buffer
}

function parseCompactJws(jws: string): ParsedJws | { error: VerifyError } {
  const parts = jws.split('.')
  if (parts.length !== 3) {
    return { error: { code: 'proofMalformed', message: 'jws is not a compact JWS (expected 3 parts)' } }
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts

  // A detached payload (the JSON-LD Data Integrity convention of an empty
  // middle segment) is not supported. It would mean reconstructing the signing
  // input from the document, and this endpoint's whole point is comparing what
  // was signed against what arrived — so it must read the signed bytes.
  if (encodedPayload.length === 0) {
    return { error: { code: 'proofMalformed', message: 'jws has a detached payload, which is not supported' } }
  }

  let header: Json
  let payload: Json
  try {
    header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf-8'))
    payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf-8'))
  } catch {
    return { error: { code: 'proofMalformed', message: 'jws header or payload is not valid JSON' } }
  }
  if (!isObject(header) || !isObject(payload)) {
    return { error: { code: 'proofMalformed', message: 'jws header and payload must be JSON objects' } }
  }
  if (!isNonEmptyString(header.alg)) {
    return { error: { code: 'proofMalformed', message: 'jws header has no alg' } }
  }
  // `crit` names header parameters the verifier MUST understand (RFC 7515 §4.1.11).
  // We understand none of them, so a token declaring any must be rejected rather
  // than verified while ignoring the extension its signer considered essential.
  if (header.crit !== undefined) {
    return {
      error: { code: 'proofMalformed', message: 'jws declares crit header parameters this verifier does not implement' },
    }
  }
  // `b64: false` changes what bytes the signature covers. Unhandled, it would
  // mean verifying over a signing input the signer never produced.
  if (header.b64 !== undefined) {
    return { error: { code: 'proofMalformed', message: 'jws sets b64, which is not supported' } }
  }

  return {
    header: { alg: header.alg },
    payload,
    signingInput: Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
    signature: Buffer.from(encodedSignature, 'base64url'),
  }
}

function verifySignature(key: ImportedKey, alg: string, signingInput: Buffer, signature: Buffer): boolean {
  try {
    switch (alg) {
      case 'EdDSA':
        return nodeVerify(null, signingInput, key.key, signature)
      case 'ES256':
        // JWS carries ECDSA signatures as raw R‖S (RFC 7518 §3.4), not DER.
        // Without `ieee-p1363` node reads them as DER and every valid
        // signature fails — a verifier that rejects everything looks safe and
        // is just as broken as one that accepts everything.
        return nodeVerify('sha256', signingInput, { key: key.key, dsaEncoding: 'ieee-p1363' }, signature)
      case 'ES384':
        return nodeVerify('sha384', signingInput, { key: key.key, dsaEncoding: 'ieee-p1363' }, signature)
      case 'RS256':
        return nodeVerify('sha256', signingInput, key.key, signature)
      case 'PS256':
        return nodeVerify(
          'sha256',
          signingInput,
          { key: key.key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
          signature,
        )
      default:
        return false
    }
  } catch {
    // A malformed signature makes node throw rather than return false. Both
    // mean the same thing here.
    return false
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
