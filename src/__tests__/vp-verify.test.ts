/**
 * SOC-181 — `POST /1.0/verify`.
 *
 * ## Why the presentations here are signed by `jose`
 *
 * Every fixture is produced by `jose`, a library nobody in this workspace
 * wrote, from freshly generated keys. That is the ticket's hardest acceptance
 * criterion and it is the one that decides whether this file is evidence.
 *
 * Had the fixtures been signed by our own wallet code, a mistake shared
 * between signer and verifier — the two most likely places for the same wrong
 * assumption to live, because the same person writes them on the same
 * afternoon — would produce a green suite. That is precisely how
 * `attestto-trust` came to accept a forged national CA root with a full green
 * board: consistency between our halves was measured, authenticity was not.
 * `jose` implements RFC 7515 without reference to anything here, so agreement
 * with it is agreement with the standard.
 *
 * ## Why the binding tests rewrite the proof's plaintext fields
 *
 * The interesting tests are not "a corrupted signature fails". They are the
 * ones where the signature is completely valid and the presentation must still
 * be rejected: a proof that says `challenge: <what you asked for>` on the
 * outside while the signed payload says something else. A verifier that
 * checked the signature and then read `proof.challenge` passes every naive
 * test and fails these, which is the difference the ticket calls "worse than
 * the 404".
 */
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, generateKeyPair, exportJWK, type CryptoKey } from 'jose'
import bs58 from 'bs58'
import { verifyPresentation } from '../vp-verify.js'

const CHALLENGE = 'c4a1f0d2-9c1e-4c2a-9f31-6a0b8f2d5e77'
const DOMAIN = 'https://verify.attestto.com'
const NOW = Date.parse('2026-08-12T12:00:00Z')

const SNS_DID = 'did:sns:alice.crbank'
const SNS_VM = `${SNS_DID}#solana-key`
const JWK_DID = 'did:sns:bob.crbank'
const JWK_VM = `${JWK_DID}#key-0`

const CREDENTIAL = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  'type': ['VerifiableCredential', 'EmploymentCredential'],
  'issuer': 'did:sns:crbank',
  'issuanceDate': '2026-01-01T00:00:00Z',
  'credentialSubject': { id: SNS_DID, role: 'Analyst' },
}

type Json = Record<string, unknown>

interface Signer {
  did: string
  verificationMethod: string
  alg: string
  privateKey: CryptoKey
  document: Json
}

/** ed25519 raw bytes, multicodec-tagged, base58btc — what `did:sns` publishes. */
function toMultibase(rawKey: Uint8Array): string {
  const tagged = new Uint8Array(2 + rawKey.length)
  tagged.set([0xed, 0x01], 0)
  tagged.set(rawKey, 2)
  return `z${bs58.encode(tagged)}`
}

/** A `did:sns`-shaped document: ed25519 owner key as `publicKeyMultibase`. */
async function ed25519Signer(): Promise<Signer> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  })
  const jwk = await exportJWK(publicKey)
  const raw = Buffer.from(jwk.x as string, 'base64url')
  return {
    did: SNS_DID,
    verificationMethod: SNS_VM,
    alg: 'EdDSA',
    privateKey,
    document: {
      id: SNS_DID,
      verificationMethod: [
        {
          id: SNS_VM,
          type: 'Ed25519VerificationKey2020',
          controller: SNS_DID,
          publicKeyMultibase: toMultibase(new Uint8Array(raw)),
        },
      ],
      authentication: [SNS_VM],
      assertionMethod: [SNS_VM],
    },
  }
}

/** A document publishing a P-256 key as `publicKeyJwk` — the wallet's ES256 path. */
async function p256Signer(): Promise<Signer> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true })
  const jwk = await exportJWK(publicKey)
  return {
    did: JWK_DID,
    verificationMethod: JWK_VM,
    alg: 'ES256',
    privateKey,
    document: {
      id: JWK_DID,
      verificationMethod: [
        { id: JWK_VM, type: 'JsonWebKey2020', controller: JWK_DID, publicKeyJwk: jwk },
      ],
      authentication: [JWK_VM],
    },
  }
}

interface PresentationOverrides {
  challenge?: string
  domain?: string
  signedNonce?: string
  signedAudience?: string
  iat?: number
  verificationMethod?: string
  proofPurpose?: string
  credentials?: unknown[]
  /** Applied to the finished presentation, AFTER signing. */
  tamper?: (vp: Json) => Json
}

/**
 * Build a presentation the way `createChapiVp` does: the signature covers a
 * JWT payload carrying the envelope, the nonce and the audience; the proof
 * object repeats the challenge and domain in the clear beside it.
 */
async function present(signer: Signer, overrides: PresentationOverrides = {}): Promise<Json> {
  const envelope = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    'type': ['VerifiablePresentation'],
    'holder': signer.did,
    'verifiableCredential': overrides.credentials ?? [CREDENTIAL],
  }
  const kid = overrides.verificationMethod ?? signer.verificationMethod
  const iat = overrides.iat ?? Math.floor(NOW / 1000)

  const jws = await new SignJWT({
    vp: envelope,
    nonce: overrides.signedNonce ?? CHALLENGE,
    iat,
    iss: signer.did,
    aud: overrides.signedAudience ?? DOMAIN,
  })
    .setProtectedHeader({ alg: signer.alg, typ: 'JWT', kid })
    .sign(signer.privateKey)

  const vp: Json = {
    ...envelope,
    proof: {
      type: 'EcdsaSecp256r1Signature2019',
      created: new Date(NOW).toISOString(),
      challenge: overrides.challenge ?? CHALLENGE,
      domain: overrides.domain ?? DOMAIN,
      proofPurpose: overrides.proofPurpose ?? 'authentication',
      verificationMethod: kid,
      jws,
    },
  }
  return overrides.tamper ? overrides.tamper(vp) : vp
}

const resolverFor =
  (...signers: Signer[]) =>
  async (did: string) =>
    signers.find((s) => s.did === did)?.document ?? null

const check = (vp: Json, resolve: (did: string) => Promise<Json | null>, body: Json = {}) =>
  verifyPresentation(
    { verifiablePresentation: vp, expectedChallenge: CHALLENGE, expectedDomain: DOMAIN, ...body },
    resolve,
    { now: NOW },
  )

let ed: Signer
let p256: Signer
let resolve: (did: string) => Promise<Json | null>

before(async () => {
  ed = await ed25519Signer()
  p256 = await p256Signer()
  resolve = resolverFor(ed, p256)
})

describe('a genuine presentation verifies', () => {
  it('accepts an ed25519 proof against a publicKeyMultibase key', async () => {
    const result = await check(await present(ed), resolve)
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    assert.equal(result.holder, SNS_DID)
  })

  it('accepts an ES256 proof against a publicKeyJwk key', async () => {
    const result = await check(await present(p256), resolve)
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
  })

  it('is not vacuous: the same fixture fails against the other holder key', async () => {
    // Both signers publish a well-formed document and both presentations are
    // correctly signed. Swapping the key material behind the same DID must
    // reject, or the two tests above would pass for a verifier that never
    // checks a signature at all.
    const wrongKey = await ed25519Signer()
    const document = { ...wrongKey.document, id: SNS_DID }
    const result = await check(await present(ed), async () => document)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'signatureInvalid')
  })
})

describe('binding is enforced against the SIGNED claims, not the proof metadata', () => {
  // These are the tests that separate this endpoint from the local check it
  // backstops. Each presentation below is CORRECTLY SIGNED and its visible
  // proof fields match exactly what the verifier asked for.

  it('rejects a proof whose signed nonce differs from the challenge it advertises', async () => {
    const vp = await present(ed, { challenge: CHALLENGE, signedNonce: 'someone-elses-challenge' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'challengeUnbound')
  })

  it('rejects a proof whose signed audience differs from the domain it advertises', async () => {
    const vp = await present(ed, { domain: DOMAIN, signedAudience: 'https://evil.example' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'domainUnbound')
  })

  it('rejects a presentation captured for another challenge', async () => {
    const vp = await present(ed, { challenge: 'old', signedNonce: 'old' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'challengeMismatch')
  })

  it('refuses to verify anything against a blank expectation', async () => {
    const vp = await present(ed)
    const blank = await verifyPresentation(
      { verifiablePresentation: vp, expectedChallenge: '', expectedDomain: DOMAIN },
      resolve,
      { now: NOW },
    )
    assert.equal(blank.valid, false)
    assert.equal(blank.errors[0].code, 'invalidRequest')
  })

  it('rejects a presentation signed outside the freshness window', async () => {
    const vp = await present(ed, { iat: Math.floor(NOW / 1000) - 3600 })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'proofNotFresh')
  })
})

describe('the signature must cover the document that arrived', () => {
  it('rejects credentials swapped in after signing', async () => {
    const forged = { ...CREDENTIAL, credentialSubject: { id: SNS_DID, role: 'Director' } }
    const vp = await present(ed, {
      tamper: (p) => ({ ...p, verifiableCredential: [forged] }),
    })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'documentAltered')
  })

  it('accepts a re-serialized document with different key order', async () => {
    // The control for the test above. Canonical comparison must not reject a
    // presentation that merely round-tripped through a different JSON writer,
    // or every real client fails and the check gets removed as broken.
    const vp = await present(ed)
    const reordered = JSON.parse(
      JSON.stringify(vp, ['proof', 'jws', 'type', 'created', 'challenge', 'domain', 'proofPurpose',
        'verificationMethod', 'holder', 'verifiableCredential', '@context', 'issuer',
        'issuanceDate', 'credentialSubject', 'id', 'role']),
    ) as Json
    const result = await check(reordered, resolve)
    assert.equal(result.valid, true)
  })
})

describe('the key is the one the proof names, in the holder\'s own document', () => {
  it('rejects a verificationMethod with no fragment', async () => {
    const vp = await present(ed, { verificationMethod: SNS_DID })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'verificationMethodNotAKey')
  })

  it('rejects a fragment that is not in the document', async () => {
    const vp = await present(ed, { verificationMethod: `${SNS_DID}#key-1` })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'keyNotAuthorized')
  })

  it('rejects a key belonging to another DID', async () => {
    const vp = await present(ed, { verificationMethod: JWK_VM })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'verificationMethodForeign')
  })

  it('rejects a key published but not authorized for authentication', async () => {
    // The key is in `verificationMethod` and signed the proof. It is not listed
    // under `authentication`, so it is written down, not authorized to log in.
    const document = { ...ed.document, authentication: [] }
    const result = await check(await present(ed), async () => document)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'keyNotAuthorized')
  })

  it('rejects a proof made for a purpose other than authentication', async () => {
    const vp = await present(ed, { proofPurpose: 'assertionMethod' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'proofPurposeInvalid')
  })

  it('rejects a holder this resolver cannot resolve', async () => {
    const result = await check(await present(ed), async () => null)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'holderUnresolvable')
  })
})

describe('the algorithm comes from the resolved key, never from the header', () => {
  const reheader = (vp: Json, header: Json): Json => {
    const proof = { ...(vp.proof as Json) }
    const [, payload, signature] = (proof.jws as string).split('.')
    proof.jws = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${payload}.${signature}`
    return { ...vp, proof }
  }

  it('rejects alg: none', async () => {
    const vp = reheader(await present(ed), { alg: 'none', typ: 'JWT' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'algorithmNotPermitted')
  })

  it('rejects an HMAC alg over an asymmetric key', async () => {
    // The algorithm-confusion attack: anyone can read the public key out of
    // the DID document and HMAC with it. Accepting HS256 here would let any
    // reader of a public document mint a valid login for its owner.
    const vp = reheader(await present(ed), { alg: 'HS256', typ: 'JWT' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'algorithmNotPermitted')
  })

  it('rejects an alg the resolved key cannot produce', async () => {
    const vp = reheader(await present(ed), { alg: 'ES256', typ: 'JWT' })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'algorithmNotPermitted')
  })

  it('rejects a jws declaring crit parameters', async () => {
    const vp = reheader(await present(ed), { alg: 'EdDSA', typ: 'JWT', crit: ['b64'], b64: false })
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'proofMalformed')
  })
})

describe('every proof must verify, not merely one of them', () => {
  it('rejects a good proof presented beside a forged one', async () => {
    const good = await present(ed)
    const forged = { ...(good.proof as Json), jws: (good.proof as Json).jws + 'x' }
    const vp = { ...good, proof: [good.proof, forged] }
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
  })

  it('rejects a presentation with no proof at all', async () => {
    const vp = await present(ed)
    delete vp.proof
    const result = await check(vp, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'proofMissing')
  })

  it('accepts the same presentation once the forged proof is removed', async () => {
    // The control: the rejection above must be caused by the forged proof, not
    // by the array shape.
    const good = await present(ed)
    const result = await check({ ...good, proof: [good.proof] }, resolve)
    assert.equal(result.valid, true)
  })
})

describe('malformed input never throws', () => {
  for (const [name, body] of [
    ['a string body', 'nope'],
    ['no presentation', {}],
    ['a presentation that is a string', { verifiablePresentation: 'nope' }],
    ['no holder', { verifiablePresentation: { proof: {} } }],
  ] as const) {
    it(`answers rather than crashing on ${name}`, async () => {
      const result = await verifyPresentation(
        { expectedChallenge: CHALLENGE, expectedDomain: DOMAIN, ...(body as Json) },
        resolve,
        { now: NOW },
      )
      assert.equal(result.valid, false)
      assert.ok(result.errors.length > 0)
    })
  }

  it('answers rather than crashing on a proof whose jws is not a JWS', async () => {
    const vp = await present(ed)
    const result = await check({ ...vp, proof: { ...(vp.proof as Json), jws: 'not-a-jws' } }, resolve)
    assert.equal(result.valid, false)
    assert.equal(result.errors[0].code, 'proofMalformed')
  })
})
