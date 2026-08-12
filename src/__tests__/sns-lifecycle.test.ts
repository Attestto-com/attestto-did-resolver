/**
 * SOC-173 — the three lifecycle states §9 distinguishes and the resolver does not.
 *
 * §9.2 step 9 and step 10b describe two outcomes this driver never produced,
 * and §9.5 describes a third it produced under the wrong name:
 *
 *  1. **Degraded.** A domain that exists on-chain with no `0x44494401` in its
 *     buffer is an SNS domain, not a `did:sns` identity. §9.2 permits the
 *     `notFound`-adjacent result this driver already returns — but only if it
 *     "MUST still set `degraded: true` so the distinction from a genuinely
 *     non-existent domain is preserved". It sets nothing, so the two are the
 *     same bytes on the wire and §9.1's "verifiers MUST reject fallback-only
 *     documents" is unenforceable: there is nothing to gate on.
 *
 *  2. **Deactivated.** §9.2 step 9: "If owner is zero address → return
 *     deactivated", checked BEFORE the buffer. No code reads the owner for the
 *     zero address at all, so a permanently retired identity resolves as
 *     `notFound` — or, if its buffer survives the transfer, as a live DID whose
 *     `#key-1` is the system program.
 *
 *  3. **Suspension is not deactivation.** §9.5 lists them as separate lifecycle
 *     phases: suspension is "Active flag cleared … DID remains resolvable but
 *     non-functional"; deactivation is "owner → zero address … Frozen". The
 *     resolver reports `didDocumentMetadata.deactivated = true` for a cleared
 *     ACTIVE flag, which claims the irreversible state (§9.4: "Transferring a
 *     domain to the zero address is permanent") for a reversible one — §9.5
 *     names Recovery as a phase, so a suspended DID is expected to come back.
 *
 * The whole point of the `degraded` flag is that a state a consumer must act on
 * has to be machine-readable rather than buried in a method-specific blob. The
 * same argument applies to each state below, which is why every assertion here
 * reads `didResolutionMetadata` / `didDocumentMetadata` and not `snsMetadata`.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { DidSnsResolver } from '../sns-resolver.js'

const ZERO_OWNER = Buffer.alloc(32)
const REAL_OWNER = Buffer.alloc(32, 7)

/** A NameRegistry header: parent(32) ‖ owner(32) ‖ class(32), then the buffer. */
function account(data?: Buffer, owner: Buffer = REAL_OWNER) {
  return Buffer.concat([Buffer.alloc(32), owner, Buffer.alloc(32), data ?? Buffer.alloc(0)])
}

/** A DID metadata buffer carrying the 0x44494401 magic — a REGISTERED DID. */
function registeredMetadata({ active = true } = {}) {
  const buf = Buffer.alloc(160)
  Buffer.from([0x44, 0x49, 0x44, 0x01]).copy(buf, 0)
  buf[4] = 0x02 // schema version
  buf[5] = active ? 0x01 : 0x00 // bit 0 = ACTIVE
  return buf
}

function resolverWith(result: Buffer | null) {
  return new DidSnsResolver({ fetchAccount: async () => result, now: () => 0 })
}

const DID = 'did:sns:alice.crbank'

describe('§9.2 step 10b — a domain without DID metadata is flagged degraded', () => {
  test('an existing domain with an empty buffer sets degraded and a warning', async () => {
    const out = await resolverWith(account()).resolve(DID)

    assert.equal(
      out.didResolutionMetadata.degraded,
      true,
      '§9.2: a degraded resolution MUST set degraded = true',
    )
    assert.equal(typeof out.didResolutionMetadata.warning, 'string')
    assert.ok(
      out.didResolutionMetadata.warning!.length > 0,
      '§9.2 requires a human-readable note alongside the flag',
    )
  })

  test('the notFound-adjacent shape is preserved: no document, still an error', async () => {
    // §9.2 explicitly allows this driver's existing choice — "A resolver MAY
    // instead return a notFound-adjacent result (empty didDocument) … if it
    // does, it MUST still set degraded: true". Returning the owner-key document
    // would ALSO be conformant; this asserts the choice actually made, so a
    // future change to the populated form is a deliberate one and not a drift.
    const out = await resolverWith(account()).resolve(DID)
    assert.equal(out.didDocument, null)
    assert.equal(out.didResolutionMetadata.error, 'notFound')
  })

  test('a magic-less buffer that is NOT empty is still degraded', async () => {
    // The buffer can hold anything — SNS records, a favourite colour. Only the
    // 0x44494401 write registers a DID (§9.1, §12: "registration is not
    // implicit"), so bytes alone must not read as registration.
    const out = await resolverWith(account(Buffer.alloc(200, 0xaa))).resolve(DID)
    assert.equal(out.didResolutionMetadata.degraded, true)
  })

  test('a genuinely non-existent domain is notFound and NOT degraded', async () => {
    // The control that gives the flag its meaning. If `degraded` were set on
    // every notFound it would carry no information, and the distinction §9.2
    // exists to preserve would be lost in the other direction.
    const out = await resolverWith(null).resolve(DID)
    assert.equal(out.didResolutionMetadata.error, 'notFound')
    assert.equal(
      out.didResolutionMetadata.degraded,
      undefined,
      'a domain that does not exist is absent, not degraded',
    )
  })

  test('a registered DID is not degraded', async () => {
    const out = await resolverWith(account(registeredMetadata())).resolve(DID)
    assert.equal(out.didResolutionMetadata.degraded, undefined)
    assert.ok(out.didDocument, 'a registered DID resolves to a document')
  })
})

describe('§9.2 step 9 / §9.4 — a zero-owner domain is deactivated', () => {
  test('owner = all-zero reports deactivated in didDocumentMetadata', async () => {
    const out = await resolverWith(account(undefined, ZERO_OWNER)).resolve(DID)
    assert.equal(out.didDocumentMetadata.deactivated, true)
  })

  test('the §9.4 response shape: null document, no error, HTTP 200', async () => {
    // §9.4's worked example is `didDocument: null`, `didResolutionMetadata:
    // { contentType }`, `didDocumentMetadata: { deactivated: true }`. Note it
    // carries NO `error` member, though §9.2's table lists `deactivated` as a
    // code at HTTP 200. The example wins here: `server.ts` derives its status
    // from the presence of `error`, so emitting one would turn the documented
    // 200 into a 500. The table/example tension is raised in SOC-177.
    const out = await resolverWith(account(undefined, ZERO_OWNER)).resolve(DID)
    assert.equal(out.didDocument, null)
    assert.equal(out.didResolutionMetadata.error, undefined, 'no error ⇒ server.ts returns 200')
    assert.equal(out.didResolutionMetadata.contentType, 'application/did+ld+json')
  })

  test('a zero owner outranks a written buffer', async () => {
    // Step 9 precedes step 10 in the algorithm, and it must: the buffer is not
    // erased by the ownership transfer, so a retired identity would otherwise
    // keep resolving to a live document whose owner key is the system program.
    const out = await resolverWith(account(registeredMetadata(), ZERO_OWNER)).resolve(DID)
    assert.equal(out.didDocumentMetadata.deactivated, true)
    assert.equal(out.didDocument, null, 'a deactivated DID must not present verification methods')
  })

  test('a zero owner is deactivated, not degraded', async () => {
    // Both conditions hold for an empty buffer under a zero owner. They are not
    // the same claim — degraded means "never registered", deactivated means
    // "registered and permanently retired" — and step 9 decides.
    const out = await resolverWith(account(undefined, ZERO_OWNER)).resolve(DID)
    assert.equal(out.didResolutionMetadata.degraded, undefined)
  })
})

describe('§9.5 — a cleared ACTIVE flag is suspension, not deactivation', () => {
  test('a suspended DID does NOT claim deactivated', async () => {
    // Deactivation is irreversible by construction (§9.4: the SNS program does
    // not support reclaiming a zero-owner domain). Suspension has a documented
    // Recovery phase. Reporting one as the other tells a consumer an identity
    // is permanently gone when it is on a compliance hold.
    const out = await resolverWith(account(registeredMetadata({ active: false }))).resolve(DID)
    assert.equal(
      out.didDocumentMetadata.deactivated,
      undefined,
      '§9.5: deactivated is reserved for the zero-owner state',
    )
  })

  test('a suspended DID remains resolvable, and says so', async () => {
    // §9.5: "DID remains resolvable but non-functional". The document is
    // returned; the non-functional half must be visible without did:sns
    // knowledge, so it goes in a `warning` — the same generic-consumer argument
    // §9.2 makes for `degraded`. The spec defines no machine-readable member
    // for suspension; that gap is SOC-177, and nothing is invented here.
    const out = await resolverWith(account(registeredMetadata({ active: false }))).resolve(DID)
    assert.ok(out.didDocument, 'suspension does not remove the document')
    assert.match(out.didResolutionMetadata.warning ?? '', /suspend/i)
  })

  test('an active DID carries no suspension warning', async () => {
    const out = await resolverWith(account(registeredMetadata({ active: true }))).resolve(DID)
    assert.equal(out.didResolutionMetadata.warning, undefined)
    assert.equal(out.didDocumentMetadata.deactivated, undefined)
  })
})
