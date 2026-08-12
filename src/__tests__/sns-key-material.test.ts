/**
 * SOC-174 — the did:sns owner key: `#solana-key`, and key material a JSON-LD
 * processor can actually see.
 *
 * Two defects in one verification method.
 *
 * **The fragment.** §8.5's vocabulary for the Solana owner key is
 * `#solana-key`; the resolver emitted `#key-1`, a name that appears nowhere in
 * the did:sns spec. The adversarial reviewer was right that this is not a MUST
 * violation — §8.5 is a non-exhaustive table whose only MUST is conditional
 * ("When present, `#solana-key` MUST correspond to the SNS domain owner's
 * Solana public key"). So it is an interoperability divergence, recorded
 * honestly as such, and fixed because the cost of fixing it is at its minimum
 * right now.
 *
 * **The encoding is the real defect, and it is not a matter of taste.**
 * §8.1 has the document declare `https://w3id.org/security/suites/ed25519-2020/v1`,
 * and every §8.2/§8.3/§8.4 example carries `publicKeyMultibase` (`z6Mk…`). The
 * resolver emitted `publicKeyBase58`. That term **is not defined in the context
 * the document itself declares** — verified below against the W3C-published
 * context file, not against anything we wrote — so a JSON-LD processor drops
 * the property and the verification method expands with NO KEY MATERIAL AT ALL.
 * §13 promises "any JSON-LD processor can expand did:sns documents".
 *
 * base58 is also not multibase: no `z` prefix, no multicodec header. Even a
 * lenient consumer that ignored the context would decode 32 raw bytes where the
 * suite specifies 34 (`0xed 0x01` ‖ key), so the two encodings are not
 * interchangeable by accident either.
 *
 * The independent referent matters here. An assertion that our document
 * contains the string we just wrote proves nothing — that is the vacuous-green
 * pattern this repo keeps finding. So the expansion test runs a real JSON-LD
 * processor over the real published contexts, and the round-trip test decodes
 * the multibase value back to the 32 owner bytes the account header carried.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import bs58 from 'bs58'
// `jsonld` is CommonJS with no bundled types. A namespace import yields the
// module record, not the exports, so `jsonld.expand` is undefined — which cost
// one confusing red before the assertion under test was ever reached.
// @ts-expect-error — no @types/jsonld; the default export is the module.
import jsonld from 'jsonld'
import { DidSnsResolver } from '../sns-resolver.js'
import { solanaAddressToMultibase } from '../multibase.js'

const MAGIC = Buffer.from([0x44, 0x49, 0x44, 0x01])

/** A distinctive owner key: 32 bytes, so its base58 form is unmistakable. */
const OWNER_BYTES = Buffer.alloc(32, 7)

function account(data?: Buffer) {
  return Buffer.concat([
    Buffer.alloc(32),
    OWNER_BYTES,
    Buffer.alloc(32),
    data ?? Buffer.alloc(0),
  ])
}

/** A v2 DID metadata buffer with the magic bytes — a REGISTERED DID. */
function registered(mutate?: (b: Buffer) => void) {
  const buf = Buffer.alloc(160)
  MAGIC.copy(buf, 0)
  buf[4] = 0x02
  buf[5] = 0x01
  mutate?.(buf)
  return buf
}

function resolverOver(data?: Buffer) {
  return new DidSnsResolver({ fetchAccount: async () => account(data), now: () => 0 })
}

async function resolveDoc(data?: Buffer) {
  const out = await resolverOver(data ?? registered()).resolve('did:sns:alice.crbank')
  assert.ok(out.didDocument, 'fixture should resolve to a document')
  // Through `unknown`: `DidDocument` has no index signature, and these tests
  // deliberately read the document as untyped JSON — the shape a consumer sees.
  return out.didDocument as unknown as Record<string, unknown>
}

// ── §8.5 — the fragment ─────────────────────────────────────────────────────

describe('§8.5 — the owner key is #solana-key', () => {
  test('the verification method is #solana-key, and #key-1 is gone entirely', async () => {
    const doc = await resolveDoc()
    const vms = doc.verificationMethod as Array<Record<string, unknown>>

    assert.equal(vms[0].id, 'did:sns:alice.crbank#solana-key')
    // Not just the id: a leftover in authentication or assertionMethod is the
    // same divergence, and a rename that misses a reference is worse than none.
    assert.ok(
      !JSON.stringify(doc).includes('#key-1'),
      `#key-1 still appears somewhere in the document: ${JSON.stringify(doc)}`,
    )
  })

  test('authentication and assertionMethod point at the method that exists', async () => {
    const doc = await resolveDoc()
    const vms = doc.verificationMethod as Array<Record<string, unknown>>
    const ids = new Set(vms.map(v => v.id))

    for (const rel of ['authentication', 'assertionMethod'] as const) {
      for (const ref of doc[rel] as string[]) {
        assert.ok(ids.has(ref), `${rel} references ${ref}, which is not in verificationMethod`)
      }
    }
  })
})

// ── §8.2 — the encoding ─────────────────────────────────────────────────────

describe('§8.2 — publicKeyMultibase, and it decodes to the owner', () => {
  test('the key is multibase-encoded and round-trips to the account header bytes', async () => {
    const doc = await resolveDoc()
    const vm = (doc.verificationMethod as Array<Record<string, unknown>>)[0]

    assert.equal(vm.type, 'Ed25519VerificationKey2020')
    assert.equal(vm.publicKeyBase58, undefined, 'publicKeyBase58 must not be emitted')

    const mb = vm.publicKeyMultibase as string
    assert.match(mb, /^z6Mk/, `not an ed25519 multibase value: ${mb}`)

    // The independent referent: decode it back and compare against the bytes
    // the account header actually held, not against anything we formatted.
    const decoded = Buffer.from(bs58.decode(mb.slice(1)))
    assert.equal(decoded.length, 34, 'multicodec prefix + 32 key bytes')
    assert.deepEqual(
      [decoded[0], decoded[1]],
      [0xed, 0x01],
      'ed25519-pub multicodec header missing',
    )
    assert.deepEqual(decoded.subarray(2), OWNER_BYTES, 'decoded key is not the domain owner')
  })
})

describe('the encoder refuses rather than emitting an undecodable key', () => {
  // These guards are NOT reachable through `resolve()` — the owner always
  // arrives as `new PublicKey(bytes).toBase58()`, so it is 32 valid bytes by
  // construction. They are the module's contract with any future caller, and
  // an untested guard is indistinguishable from an absent one. Tested against
  // the unit directly, because that is where the contract lives.
  test('a non-base58 key throws instead of producing a value', () => {
    assert.throws(() => solanaAddressToMultibase('not-base58-0OIl'), /not base58/)
  })

  test('a key of the wrong length throws — 34 bytes is not an Ed25519 key', () => {
    // 34 bytes: what you get if someone passes an already-multicodec-tagged
    // key back in and double-encodes it.
    const tagged = bs58.encode(Buffer.alloc(34, 1))
    assert.throws(() => solanaAddressToMultibase(tagged), /34 bytes, expected 32/)
  })
})

// ── §13 — a real JSON-LD processor ──────────────────────────────────────────

const CONTEXTS = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'contexts')

/**
 * Offline loader over the contexts as published. Fetching them at test time
 * would make this suite fail on a network blip and, worse, pass for the wrong
 * reason if a future context started defining `publicKeyBase58`. Pinned files
 * make the referent stable AND external — the property that matters.
 */
const LOADER: Record<string, string> = {
  'https://www.w3.org/ns/did/v1': 'did-v1.jsonld',
  'https://w3id.org/security/suites/ed25519-2020/v1': 'ed25519-2020-v1.jsonld',
}

async function documentLoader(url: string) {
  const file = LOADER[url]
  assert.ok(file, `document declares a context this test has not pinned: ${url}`)
  return {
    contextUrl: undefined,
    documentUrl: url,
    document: JSON.parse(readFileSync(join(CONTEXTS, file), 'utf-8')),
  }
}

describe('§13 — any JSON-LD processor can expand the document', () => {
  test('the published ed25519-2020 context defines publicKeyMultibase and NOT publicKeyBase58', () => {
    // The premise, asserted separately so a failure here reads as "the
    // W3C context changed" rather than "our resolver is wrong".
    const ctx = readFileSync(join(CONTEXTS, 'ed25519-2020-v1.jsonld'), 'utf-8')
    assert.ok(ctx.includes('publicKeyMultibase'), 'context no longer defines publicKeyMultibase')
    assert.ok(
      !ctx.includes('publicKeyBase58'),
      'the context now defines publicKeyBase58 — this ticket\'s premise needs re-checking',
    )
  })

  test('the verification method survives expansion WITH its key material', async () => {
    const doc = await resolveDoc()
    const expanded = (await jsonld.expand(doc, { documentLoader })) as Array<
      Record<string, unknown>
    >

    const SEC = 'https://w3id.org/security#'
    const vms = expanded[0][`${SEC}verificationMethod`] as Array<Record<string, unknown>>
    assert.ok(vms?.length, 'verificationMethod did not survive expansion at all')

    const material = vms[0][`${SEC}publicKeyMultibase`]
    assert.ok(
      material,
      'the verification method expanded with NO key material — a JSON-LD ' +
        'processor dropped the key, which is exactly what publicKeyBase58 did',
    )
  })

  test('every declared context is one the document actually uses', async () => {
    // An undeclared term is a silent drop; a declared-but-unused context is a
    // fetch every verifier pays for and a set of terms nobody audited. The
    // document used to declare secp256k1-2019 and x25519-2020 while emitting
    // neither. documentLoader throws on anything unpinned, so expansion
    // succeeding IS the assertion — this test states why.
    const doc = await resolveDoc()
    for (const url of doc['@context'] as string[]) {
      assert.ok(LOADER[url], `declared but unused context: ${url}`)
    }
  })
})

// ── The ECIES key ───────────────────────────────────────────────────────────

describe('the ECIES key is not emitted as a verification method', () => {
  const withEcies = () =>
    registered(b => {
      // §10: offset 38 within the metadata buffer, 33 bytes, compressed secp256k1.
      Buffer.alloc(33, 0xab).copy(b, 38)
    })

  test('no #ecies-key verification method, and no malformed multibase', async () => {
    const doc = await resolveDoc(withEcies())

    assert.ok(
      !JSON.stringify(doc).includes('ecies-key'),
      'the ECIES key is still emitted as a verification method',
    )
    // The old value was `"z" + hex` — `z` declares base58btc over a payload of
    // 66 hex characters, so every conforming decoder either throws or yields
    // unrelated bytes. There is no correct type or fragment to emit it under:
    // §8.5 has no row for it, and §12's PQ table names `#ecies-key` without
    // giving it a type or an encoding. Per Rule 0 the resolver does not pick
    // one — it does not emit it. Filed as a spec gap under SOC-177.
    assert.equal(doc.keyAgreement, undefined, 'keyAgreement held a signature-suite key')
  })

  test('the value is still reported, in metadata that claims no encoding', async () => {
    // Dropping the method must not drop the data. §10 defines the field; a
    // consumer that knows what it is can still read it, the way the vault hash
    // is reported without pretending to be a service endpoint.
    const out = await resolverOver(withEcies()).resolve('did:sns:alice.crbank')
    const sns = out.didResolutionMetadata.snsMetadata as Record<string, unknown>
    const meta = sns.didMetadata as Record<string, unknown>

    assert.equal(meta.eciesPublicKey, 'ab'.repeat(33))
  })
})
