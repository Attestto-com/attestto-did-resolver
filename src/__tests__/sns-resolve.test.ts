/**
 * SOC-171 — the resolver's use of the conformant parser, and the account lookup
 * that follows from it (§9.2 steps 1-6).
 *
 * These tests exist because `DidSnsResolver` could not be exercised at all: it
 * built its own `Connection` inline, so every path through it required a Solana
 * RPC. An injected account reader removes that, and the reader also lets the
 * tests observe WHICH address was derived — which is the only way to catch the
 * `.sol` bug without re-implementing PDA derivation in the test and asserting
 * the code agrees with itself.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { DidSnsResolver } from '../sns-resolver.js'

/** A NameRegistry header: parent(32) ‖ owner(32) ‖ class(32), then the buffer. */
function account(opts: { owner?: Buffer; data?: Buffer } = {}) {
  const owner = opts.owner ?? Buffer.alloc(32, 7)
  return Buffer.concat([Buffer.alloc(32), owner, Buffer.alloc(32), opts.data ?? Buffer.alloc(0)])
}

/** Records every address asked for, so the test can compare derivations. */
function reader(result: Buffer | null) {
  const asked: string[] = []
  return {
    asked,
    fetchAccount: async (address: string) => {
      asked.push(address)
      return result
    },
  }
}

function resolverWith(result: Buffer | null) {
  const r = reader(result)
  return { r, resolver: new DidSnsResolver({ fetchAccount: r.fetchAccount, now: () => 0 }) }
}

describe('§9.2 steps 1-3 — malformed identifiers never reach the chain', () => {
  test('a syntactically invalid DID is invalidDid and costs no RPC call', async () => {
    for (const did of ['did:sns:bad_underscore', 'did:sns:alice.', 'did:sns:mainnet', 'did:web:x']) {
      const { r, resolver } = resolverWith(account())
      const out = await resolver.resolve(did)
      assert.equal(out.didResolutionMetadata.error, 'invalidDid', did)
      assert.equal(out.didDocument, null, did)
      // The point of parsing first: a malformed name must not become a PDA
      // lookup. Today `did:sns:alice.` derives a key from an empty label.
      assert.deepEqual(r.asked, [], `${did} should not have hit the chain`)
    }
  })

  test('§7.2: an over-deep name is refused and costs no RPC call', async () => {
    const { r, resolver } = resolverWith(account())
    const out = await resolver.resolve('did:sns:dept.alice.crbank')
    assert.equal(out.didDocument, null)
    assert.ok(out.didResolutionMetadata.error, 'must carry an error')
    assert.deepEqual(r.asked, [])
  })
})

describe('§9.2 step 2 — the suffix changes the lookup, not the identity', () => {
  test('suffixed and unsuffixed spellings derive the SAME account', async () => {
    // The assertion that catches the live bug without re-deriving the PDA here:
    // whatever address the implementation computes, both spellings must compute
    // the same one. Today `alice.attestto.sol` is rejected outright and
    // `attestto.sol` is hashed as a subdomain of `sol`.
    const a = resolverWith(account())
    await a.resolver.resolve('did:sns:alice.attestto')
    const b = resolverWith(account())
    await b.resolver.resolve('did:sns:alice.attestto.sol')

    assert.equal(a.r.asked.length, 1, 'one lookup for the unsuffixed form')
    assert.deepEqual(b.r.asked, a.r.asked, 'the suffix must not change the address')
  })

  test('a root name with the suffix is not looked up as a subdomain of "sol"', async () => {
    const a = resolverWith(account())
    await a.resolver.resolve('did:sns:attestto')
    const b = resolverWith(account())
    await b.resolver.resolve('did:sns:attestto.sol')
    assert.deepEqual(b.r.asked, a.r.asked)
  })

  test('a root and a subdomain of the same label derive DIFFERENT accounts', async () => {
    // Guards the inverse: a strip that collapsed too much would make
    // `alice.attestto` and `attestto` the same lookup.
    const a = resolverWith(account())
    await a.resolver.resolve('did:sns:attestto')
    const b = resolverWith(account())
    await b.resolver.resolve('did:sns:alice.attestto')
    assert.notDeepEqual(b.r.asked, a.r.asked)
  })
})

describe('§9.2 steps 4-5 — the derived address is externally correct', () => {
  /**
   * An EXTERNAL referent for PDA derivation.
   *
   * Every other assertion in this file compares two derivations against each
   * other, which proves the derivation is *consistent* — not that it is right.
   * Verified by mutation: corrupting the name before derivation (replacing `.`
   * with `-`) left all of those tests green, because both sides moved together.
   * That is the same self-agreement defect this repo keeps shipping.
   *
   * This constant is not computed here. It was obtained by deriving the address
   * and then confirming against Solana mainnet (`getAccountInfo`) that an
   * account exists at it, 1096 bytes, whose owner field (bytes 32-63) is
   * `Att2w54agJRkbK7hiDfuMpk8mqSeEqSiA1UQZZnCUZEs` — the same owner
   * `resolver.attestto.com` reports for `did:sns:attestto`. A wrong derivation
   * points at an address with no account on it.
   *
   * Re-verify with:
   *   curl -s https://api.mainnet-beta.solana.com -H 'Content-Type: application/json' \
   *     -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo",
   *          "params":["G4NCT9nBjzGxveLyCnxFhoUSwVysozomibZq7WudNJJ6",{"encoding":"base64"}]}'
   */
  const ATTESTTO_SOL_ACCOUNT = 'G4NCT9nBjzGxveLyCnxFhoUSwVysozomibZq7WudNJJ6'

  /**
   * A real SUBDOMAIN, which the root above cannot substitute for: subdomain
   * derivation is a different code path (hash the parent, then hash `\0child`
   * against the parent key). Verified the same way — account exists, 96 bytes,
   * owner `6V3DAZhWgATw8hrmMh7DnvLgaVpHLuMafZZPTVnyUs6Y`, matching what
   * `resolver.attestto.com` reports for `did:sns:eduardo.attestto`.
   *
   * This constant is what finally kills the mutation that corrupts the name
   * before derivation: a root name has no dot, so a `.`→`-` mutation leaves it
   * untouched and every root-only assertion stays green.
   */
  const EDUARDO_ATTESTTO_ACCOUNT = '8BDeCuKLBRP9x5f9ttnN3fkJWnWfT7ds7Bg7G5EWv7Eq'

  test('did:sns:attestto derives the real on-chain account for attestto.sol', async () => {
    const { r, resolver } = resolverWith(account())
    await resolver.resolve('did:sns:attestto')
    assert.deepEqual(r.asked, [ATTESTTO_SOL_ACCOUNT])
  })

  test('the .sol spelling derives that same real account', async () => {
    const { r, resolver } = resolverWith(account())
    await resolver.resolve('did:sns:attestto.sol')
    assert.deepEqual(r.asked, [ATTESTTO_SOL_ACCOUNT])
  })

  test('a subdomain derives its real on-chain account', async () => {
    const { r, resolver } = resolverWith(account())
    await resolver.resolve('did:sns:eduardo.attestto')
    assert.deepEqual(r.asked, [EDUARDO_ATTESTTO_ACCOUNT])
  })

  test('the .sol spelling of a subdomain derives that same real account', async () => {
    // The end-to-end proof of the §9.2 step-2 fix against on-chain reality:
    // this is the spelling the whole workspace uses, and today it is rejected
    // outright as `invalidDid`.
    const { r, resolver } = resolverWith(account())
    await resolver.resolve('did:sns:eduardo.attestto.sol')
    assert.deepEqual(r.asked, [EDUARDO_ATTESTTO_ACCOUNT])
  })
})

describe('DID Core — the document echoes the DID that was resolved', () => {
  test('id is the input identifier, suffix and all', async () => {
    // DID Core: the document's `id` is the DID that was resolved. Whether
    // `did:sns` should define a canonical form that drops `.sol` is undecided
    // upstream (SOC-177 G7); until it is, echoing is the only choice that
    // invents nothing.
    const { resolver } = resolverWith(account())
    const out = await resolver.resolve('did:sns:alice.attestto.sol')
    assert.equal(out.didDocument?.id, 'did:sns:alice.attestto.sol')
  })
})

describe('the account reader is injected, not constructed', () => {
  test('resolution makes exactly one account read', async () => {
    const { r, resolver } = resolverWith(account())
    await resolver.resolve('did:sns:alice.attestto')
    assert.equal(r.asked.length, 1)
  })

  test('a missing account is notFound, not a crash', async () => {
    const { resolver } = resolverWith(null)
    const out = await resolver.resolve('did:sns:alice.attestto')
    assert.equal(out.didResolutionMetadata.error, 'notFound')
  })

  test('§9.2: the network selector reaches the reader', async () => {
    const seen: string[] = []
    const resolver = new DidSnsResolver({
      fetchAccount: async (_a, network) => {
        seen.push(network)
        return account()
      },
      now: () => 0,
    })
    await resolver.resolve('did:sns:devnet:alice.attestto')
    await resolver.resolve('did:sns:alice.attestto')
    assert.deepEqual(seen, ['devnet', 'mainnet'])
  })
})
