/**
 * SOC-172 — registration is an on-chain write, and a public DIF driver does not
 * advertise one operator's infrastructure in other people's documents.
 *
 * Two defects, found independently by two agents that could not see each
 * other's work:
 *
 *   1. `parsed.name.includes('attestto')` was accepted as a SUBSTITUTE for the
 *      `0x44494401` magic bytes. §9.1: "DID registration requires an on-chain
 *      write." §12: "DID registration is not implicit." A name string is not a
 *      write, and `includes` is a SUBSTRING test — `attesttofake`,
 *      `not-attestto-really` and `x.attestto-evil` all passed it.
 *   2. Service endpoints pointing at `api.attestto.com` / `app.attestto.com`
 *      were attached to every document, sourced from nothing on-chain. §1: the
 *      method is "operator-agnostic". §8.4: "Service endpoints point to the
 *      tenant's infrastructure (whitelabel)." §12.5 lists repointing service
 *      endpoints at infrastructure the subject does not control as an ATTACKER
 *      capability.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { DidSnsResolver } from '../sns-resolver.js'

const MAGIC = Buffer.from([0x44, 0x49, 0x44, 0x01])

/** A NameRegistry account: header(96) ‖ optional DID metadata. */
function account(data?: Buffer) {
  return Buffer.concat([Buffer.alloc(32), Buffer.alloc(32, 7), Buffer.alloc(32), data ?? Buffer.alloc(0)])
}

/** A v2 DID metadata buffer with the magic bytes present — a REGISTERED DID. */
function registered(flags = 0x01) {
  const buf = Buffer.alloc(160)
  MAGIC.copy(buf, 0)
  buf[4] = 0x02
  buf[5] = flags
  return buf
}

function resolverOver(data?: Buffer) {
  return new DidSnsResolver({ fetchAccount: async () => account(data), now: () => 0 })
}

/** Every string anywhere in the resolution result — services, ids, endpoints. */
function serialized(result: unknown) {
  return JSON.stringify(result)
}

describe('§9.1 / §12 — registration is the on-chain write, never the name', () => {
  for (const name of ['attesttofake', 'not-attestto-really', 'attestto-support', 'x.attestto-evil']) {
    test(`a lookalike (${name}) with an empty buffer is NOT a registered DID`, async () => {
      const out = await resolverOver().resolve(`did:sns:${name}`)
      assert.equal(
        out.didDocument,
        null,
        `${name} was treated as registered because its name contains "attestto"`,
      )
    })
  }

  test('the genuine namespace gets no special treatment either', async () => {
    // `attestto` itself, with nothing written to its buffer, is exactly as
    // unregistered as any other domain. The bypass made the vendor's own name
    // the one string that could skip the write.
    const out = await resolverOver().resolve('did:sns:attestto')
    assert.equal(out.didDocument, null)
  })

  test('a domain WITH the magic bytes resolves, whatever it is called', async () => {
    const out = await resolverOver(registered()).resolve('did:sns:somebody.crbank')
    assert.ok(out.didDocument, 'a registered domain must resolve')
    assert.equal(out.didDocument?.id, 'did:sns:somebody.crbank')
  })
})

describe('§1 / §8.4 — the driver is operator-agnostic', () => {
  test('no Attestto hostname appears in a document the buffer did not supply', async () => {
    // §3.2 Model C: an independent operator with its own infrastructure.
    const out = await resolverOver(registered()).resolve('did:sns:eve.usBank')
    const wire = serialized(out)
    for (const host of ['api.attestto.com', 'app.attestto.com', 'attestto.com']) {
      assert.ok(!wire.includes(host), `${host} was injected into a third party's document`)
    }
  })

  test('no service endpoint is invented for the vendor namespace either', async () => {
    const out = await resolverOver(registered()).resolve('did:sns:alice.attestto')
    const wire = serialized(out)
    assert.ok(!wire.includes('attestto.com'), 'hardcoded operator infrastructure')
  })

  test('the fabricated LinkedDomains URL is gone', async () => {
    // It asserted `https://<name>.sol` — a hostname in a TLD that does not
    // exist in DNS — and `LinkedDomains` is not among §8.6's service types.
    const out = await resolverOver(registered()).resolve('did:sns:alice.crbank')
    const wire = serialized(out)
    assert.ok(!wire.includes('LinkedDomains'), 'LinkedDomains is not a §8.6 service type')
    assert.ok(!wire.includes('.sol"'), 'no .sol hostname may be asserted as a linked domain')
  })
})

describe('§8.6 — service types come from the spec vocabulary', () => {
  test('every emitted service type is one §8.6 defines', async () => {
    // §8.6's table is the whole list. `EncryptedVault` (emitted) is not
    // `EncryptedDataVault` (defined), and `SasAttestation` is not there at all.
    const DEFINED = new Set([
      'EncryptedDataVault',
      'VerifiablePresentationService',
      'DIDCommMessaging',
      'GleifLookupService',
      'BitstringStatusList',
    ])
    const out = await resolverOver(registered(0x01 | 0x10)).resolve('did:sns:alice.crbank')
    const services = (out.didDocument?.service ?? []) as { type: string }[]
    for (const svc of services) {
      assert.ok(DEFINED.has(svc.type), `${svc.type} is not a §8.6 service type`)
    }
  })
})
