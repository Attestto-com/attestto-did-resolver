/**
 * SOC-181 — `POST /1.0/verify` over a real socket, and the round trip that
 * would have caught its absence.
 *
 * `vp-verify.test.ts` proves the verifier. It could pass in full while the
 * route did not exist — which is exactly the state this repo was in, with a
 * well-tested resolver underneath a server nobody could reach. The wiring is
 * the layer this epic's defects lived in, so it gets its own file.
 *
 * ## The round trip
 *
 * The last test drives the REAL `@attestto/id-wallet-adapter` (installed from
 * npm, not a local copy or a re-implementation) against the REAL request
 * handler. Nothing between the adapter's `verifyPresentation` and this
 * server's route is stubbed: the adapter resolves the holder through
 * `/1.0/identifiers`, posts the presentation to `/1.0/verify`, and reads
 * `valid` off the response exactly as a relying party does.
 *
 * The only thing faked is Solana itself, through `SOLANA_RPC_URL` pointed at a
 * local JSON-RPC that answers `getAccountInfo` with a NameRegistry account
 * whose owner is the key the presentation was signed with. That is the
 * blockchain, not our code — and it is what makes `did:sns` §8.5 true for the
 * fixture: `#solana-key` IS the domain owner.
 *
 * An assertion of `valid: true` here is the one that fails when the route is
 * missing, and it failed for months because nobody wrote it.
 */
import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { SignJWT, generateKeyPair, exportJWK } from 'jose'
import bs58 from 'bs58'

const HOLDER = 'did:sns:alice.crbank'
const VERIFICATION_METHOD = `${HOLDER}#solana-key`
const CHALLENGE = '7f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2190'

// ── The blockchain, faked ───────────────────────────────────────────
// Generated before the server is imported, because `SOLANA_RPC_URL` is read
// through `process.env` on each RPC call and the address must exist by then.

const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
  crv: 'Ed25519',
  extractable: true,
})
const ownerRaw = Buffer.from((await exportJWK(publicKey)).x as string, 'base64url')

/**
 * A SNS NameRegistry account: parentName(32) ‖ owner(32) ‖ class(32), followed
 * by the v1 DID metadata record.
 *
 * The metadata is not optional padding. A domain that exists without it
 * resolves `notFound` with `degraded: true` — an SNS name is not yet a DID.
 * The first draft of this fixture stopped at 96 bytes and the round trip
 * failed on resolution rather than on verification, which is the resolver
 * being right about `did:sns` and the fixture being wrong about it.
 *
 * v1 layout after the header: magic(4) ‖ version ‖ flags ‖ docHash(32) ‖
 * ecies(33) ‖ vaultHash(32) ‖ sbtMint(32), padded to the 160 bytes the parser
 * requires. Only `flags` matters here: ACTIVE, nothing else claimed.
 */
const didMetadata = Buffer.alloc(160)
Buffer.from([0x44, 0x49, 0x44, 0x01]).copy(didMetadata, 0) // magic
didMetadata[4] = 0x01 // version 1
didMetadata[5] = 0x01 // DID_FLAGS.ACTIVE

const registryAccount = Buffer.concat([
  Buffer.alloc(32),
  ownerRaw,
  Buffer.alloc(32),
  didMetadata,
])

const rpc = createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => (body += chunk))
  req.on('end', () => {
    const { id } = JSON.parse(body || '{}')
    res.setHeader('Content-Type', 'application/json')
    res.end(
      JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          context: { apiVersion: '2.0.0', slot: 1 },
          value: {
            data: [registryAccount.toString('base64'), 'base64'],
            executable: false,
            lamports: 1_000_000,
            owner: 'namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX',
            rentEpoch: 0,
            space: registryAccount.length,
          },
        },
      }),
    )
  })
})
await new Promise<void>((resolve) => rpc.listen(0, '127.0.0.1', resolve))
process.env.SOLANA_RPC_URL = `http://127.0.0.1:${(rpc.address() as AddressInfo).port}`

// Imported AFTER the env is set: `server.ts` builds its resolvers at module
// scope, so an import hoisted above this line would bind the public mainnet
// endpoint and the round trip would silently go to the internet.
const { requestHandler } = await import('../server.js')
const { default: whitelist } = await import('../cors-whitelist.json', { with: { type: 'json' } })
const ALLOWED_ORIGIN: string = (whitelist as { allowedOrigins: string[] }).allowedOrigins[0]

let server: Server
let base: string

before(async () => {
  server = createServer(requestHandler)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})

after(() => {
  server.close()
  rpc.close()
})

const post = (body: unknown, init: RequestInit = {}) =>
  fetch(`${base}/1.0/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
    ...init,
  })

/** A presentation in the shape `createChapiVp` emits, signed by `jose`. */
async function signedPresentation(domain: string, challenge = CHALLENGE) {
  const envelope = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    'type': ['VerifiablePresentation'],
    'holder': HOLDER,
    'verifiableCredential': [
      {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        'type': ['VerifiableCredential'],
        'issuer': 'did:sns:crbank',
        'issuanceDate': '2026-01-01T00:00:00Z',
        'credentialSubject': { id: HOLDER },
      },
    ],
  }
  const jws = await new SignJWT({
    vp: envelope,
    nonce: challenge,
    iat: Math.floor(Date.now() / 1000),
    iss: HOLDER,
    aud: domain,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: VERIFICATION_METHOD })
    .sign(privateKey)

  return {
    ...envelope,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      challenge,
      domain,
      proofPurpose: 'authentication',
      verificationMethod: VERIFICATION_METHOD,
      jws,
    },
  }
}

describe('the route exists and is reachable', () => {
  test('POST /1.0/verify is not a 404', async () => {
    // The assertion that was missing. Everything else in this file is detail;
    // this line alone distinguishes a resolver that can authenticate anyone
    // from one that authenticates nobody.
    const res = await post({
      verifiablePresentation: await signedPresentation('https://example.test'),
      expectedChallenge: CHALLENGE,
      expectedDomain: 'https://example.test',
    })
    assert.notEqual(res.status, 404)
    assert.equal(res.status, 200)
    await res.arrayBuffer()
  })

  test('GET /1.0/verify is 405 with an Allow header, not 404', async () => {
    const res = await fetch(`${base}/1.0/verify`)
    assert.equal(res.status, 405)
    assert.match(res.headers.get('allow') ?? '', /POST/)
    await res.arrayBuffer()
  })

  test('a rejected presentation is 200 with valid:false, never a 4xx', async () => {
    // The adapter checks `res.ok` before reading the body. A 4xx for "this
    // presentation does not verify" is indistinguishable from the missing
    // route, so a real rejection must not be reported as a broken request.
    const res = await post({
      verifiablePresentation: await signedPresentation('https://example.test'),
      expectedChallenge: 'a-different-challenge',
      expectedDomain: 'https://example.test',
    })
    assert.equal(res.status, 200)
    const body = (await res.json()) as { valid: boolean; errors: { code: string }[] }
    assert.equal(body.valid, false)
    assert.equal(body.errors[0].code, 'challengeMismatch')
  })

  test('a malformed body is 400 and does not throw', async () => {
    const res = await post('{ not json')
    assert.equal(res.status, 400)
    await res.arrayBuffer()
  })

  test('an oversized body is refused with 413', async () => {
    const res = await post({ padding: 'x'.repeat(300 * 1024) })
    assert.equal(res.status, 413)
    await res.arrayBuffer()
  })

  test('a browser can preflight it', async () => {
    // Without POST in Access-Control-Allow-Methods the endpoint works from
    // curl and is dead from `<attestto-login>` — a failure that reads like a
    // broken endpoint rather than a missing header.
    const res = await fetch(`${base}/1.0/verify`, {
      method: 'OPTIONS',
      headers: {
        Origin: ALLOWED_ORIGIN,
        'Access-Control-Request-Method': 'POST',
      },
    })
    assert.match(res.headers.get('access-control-allow-methods') ?? '', /POST/)
    assert.equal(res.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN)
    await res.arrayBuffer()
  })
})

describe('round trip through the real @attestto/id-wallet-adapter', () => {
  test('verifyPresentation returns valid:true against this resolver', async () => {
    const { verifyPresentation } = await import('@attestto/id-wallet-adapter')

    const domain = 'https://relying-party.test'
    const vp = await signedPresentation(domain)

    const result = await verifyPresentation(
      vp as unknown as Record<string, unknown>,
      {
        did: HOLDER,
        name: 'Attestto Credentials',
        icon: 'https://attestto.org/icon.png',
        version: '0.1.0',
        protocols: [],
        maintainer: { name: 'Attestto', url: 'https://attestto.org' },
        homepage: 'https://attestto.org',
      } as never,
      {
        resolverUrl: base,
        trustedIssuers: ['did:sns:crbank'],
        expectedChallenge: CHALLENGE,
        expectedDomain: domain,
        checkRevocation: false,
      },
    )

    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    assert.equal(result.holderDid, HOLDER)
  })

  test('and valid:false when the challenge is not the one issued', async () => {
    // The control. Without it the test above would pass against a resolver
    // that answered `{ valid: true }` unconditionally, which is the failure
    // mode this ticket warns is worse than the 404.
    const { verifyPresentation } = await import('@attestto/id-wallet-adapter')

    const domain = 'https://relying-party.test'
    const vp = await signedPresentation(domain, 'a-challenge-nobody-issued')

    const result = await verifyPresentation(
      vp as unknown as Record<string, unknown>,
      { did: HOLDER, protocols: [] } as never,
      {
        resolverUrl: base,
        trustedIssuers: ['did:sns:crbank'],
        expectedChallenge: CHALLENGE,
        expectedDomain: domain,
        checkRevocation: false,
      },
    )

    assert.equal(result.valid, false)
  })
})
