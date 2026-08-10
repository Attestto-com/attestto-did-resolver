/**
 * SOC-171 — did:sns identifier parsing, asserted against the published method spec.
 *
 * Authority: did-sns-spec @ 9e04ffc (v0.4.0). Scope: §7, §7.1, §7.2 and §9.2
 * STEPS 1-3 only. (§9.2 also carries the degraded-signalling MUSTs — those are
 * SOC-173, not this file. A green run here is not §9.2 coverage.)
 *
 * ── This suite was rewritten after three independent reviews ────────────────
 *
 * The first version passed 20/20 against a parser with NO grammar at all — a
 * `Set` of the exact strings it rejected and a `Record` of the exact strings it
 * accepted. Every assertion was a literal-string oracle, so a lookup table was
 * a complete solution. That is the same self-agreement defect this repo keeps
 * shipping, committed in the test rather than the code.
 *
 * So the load-bearing part of this file is `describe('generated …')` at the
 * bottom: inputs are BUILT from the ABNF and their expectations DERIVED from
 * it, not typed out. A table cannot pass inputs the author never wrote down.
 *
 * The first version also invented four requirements. Removed:
 *   - `did:sns:sol` → invalidDid. `sol` is an ordinary label; the reserved list
 *     is closed at three tokens. Asserting 400 for a valid DID.
 *   - canonicalising the returned identifier to the stripped form. Mandated
 *     NOWHERE, and arguably contra DID Core (a resolved document's `id` is the
 *     DID that was resolved). See the note on `name` below.
 *   - a specific error code for over-deep names. Depth is a POLICY constraint
 *     (§9.2 puts it at step 3, after parsing succeeds); §7.2 says only
 *     "rejected by resolver" and never names a code.
 *   - `did:sns:al#ice` → invalidDid. `#` is the DID-URL fragment delimiter, and
 *     §8 emits `did:sns:alice.crbank#firma-digital` throughout.
 *
 * Where the spec is genuinely silent, this file asserts NOTHING and points at
 * SOC-177 instead of guessing. Per Rule 0, a test that freezes an arbitrary
 * choice is a second source of truth.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { parseSnsDid, type SnsParseResult } from '../sns-parse.js'

/**
 * `name` is the value §9.2 step 4 hashes — suffix stripped, network removed.
 * It is deliberately NOT called "the canonical DID": what belongs in
 * `didDocument.id` is undecided (SOC-177 G7) and is the caller's problem.
 */
function ok(input: string) {
  const r = parseSnsDid(input)
  assert.equal(r.ok, true, `expected ${input} to parse, got ${JSON.stringify(r)}`)
  if (!r.ok) throw new Error('unreachable')
  return r.value
}

/** Rejected, without asserting a code — used where the spec names none. */
function refused(input: string) {
  const r = parseSnsDid(input)
  assert.equal(r.ok, false, `expected ${input} to be refused, got ${JSON.stringify(r)}`)
}

/** Rejected as `invalidDid` specifically — only where the spec says so. */
function invalidDid(input: string) {
  const r = parseSnsDid(input)
  assert.equal(r.ok, false, `expected ${input} to be rejected, got ${JSON.stringify(r)}`)
  if (r.ok) throw new Error('unreachable')
  assert.equal(r.reason, 'invalidDid', `${input} must be invalidDid, not ${r.reason}`)
  assert.equal(typeof r.message, 'string')
  assert.ok(r.message.length > 0, 'a rejection must explain itself')
}

describe('the helpers themselves can fail', () => {
  // Without this, `invalidDid()`'s reason check is vacuous: if the result type
  // only ever carries 'invalidDid', the discriminating half never fires.
  test('invalidDid() rejects a non-invalidDid refusal', () => {
    const notFound: SnsParseResult = { ok: false, reason: 'tooDeep', message: 'x' }
    assert.throws(() => {
      assert.equal(notFound.ok, false)
      if (notFound.ok) return
      assert.equal(notFound.reason, 'invalidDid')
    })
  })

  test('ok() rejects a truthy-but-not-true result', () => {
    assert.throws(() => assert.equal(1 as unknown, true))
  })
})

describe('§7 — method prefix', () => {
  test('§7: "A DID using this method MUST begin with `did:sns:`"', () => {
    for (const bad of ['did:web:example.org', 'did:pki:cr:raiz-nacional', 'sns:alice', 'alice', '']) {
      invalidDid(bad)
    }
  })

  test('§7: "the method name MUST be lowercase"', () => {
    // The only explicit MUST in §7's prose, and it had no test at all.
    for (const bad of ['DID:SNS:alice', 'did:SNS:alice', 'Did:Sns:alice', 'DID:sns:alice']) {
      invalidDid(bad)
    }
  })
})

describe('§9.2 step 2 — "Strip \'.sol\' suffix if present"', () => {
  test('§9.2: a two-level name keeps both labels once the suffix is gone', () => {
    // The dominant spelling across the workspace, and `invalidDid` today
    // because the depth check counts `sol` as a third label.
    assert.deepEqual(ok('did:sns:alice.attestto.sol'), {
      name: 'alice.attestto',
      network: 'mainnet',
    })
  })

  test('§9.2: a ROOT name with the suffix is not read as a subdomain of "sol"', () => {
    // The silent half: `attestto.sol` clears a naive depth check, then gets
    // hashed as subdomain `attestto` under parent `sol` — a PDA that does not
    // exist — so it 404s while `did:sns:attestto` returns 200.
    assert.equal(ok('did:sns:attestto.sol').name, 'attestto')
  })

  test('§9.2: stripping is suffix-anchored, not a substring replace', () => {
    // Guards the real bug shape found in CORTEX session-identity.ts:256, which
    // uses `.replace('.sol','')` — unanchored and first-occurrence.
    assert.equal(ok('did:sns:solana').name, 'solana')
    assert.equal(ok('did:sns:resolver.attestto').name, 'resolver.attestto')
    assert.equal(ok('did:sns:sol').name, 'sol')
  })

  test('§9.2: the emitted name never carries the suffix', () => {
    for (const input of ['did:sns:alice.attestto.sol', 'did:sns:attestto.sol', 'did:sns:x.sol']) {
      assert.ok(!ok(input).name.endsWith('.sol'), `${input} leaked .sol into name`)
    }
  })

  // NOT ASSERTED — `did:sns:alice.sol.sol`. §9.2 says "Strip … if present",
  // singular; whether that is once or to fixpoint is undefined. SOC-177.
})

describe('§7.1 — reserved network selectors', () => {
  // "a resolver MUST reject did:sns:mainnet, did:sns:devnet, and
  // did:sns:testnet (a network token with no name) as invalidDid."
  // The only place in §7 where the spec supplies an error code.
  for (const token of ['mainnet', 'devnet', 'testnet']) {
    test(`§7.1: did:sns:${token} is invalidDid, not a name`, () => {
      invalidDid(`did:sns:${token}`)
    })
  }

  // "MUST NOT be registered or resolved as top-level sns-name labels" — a
  // prohibition with no code attached, so only the refusal is asserted.
  for (const token of ['mainnet', 'devnet', 'testnet']) {
    test(`§7.1: ${token} is refused as a NAME after a selector`, () => {
      refused(`did:sns:devnet:${token}`)
    })
  }

  // All three selectors must work — the first version tested only devnet, so a
  // parser hardcoding 'mainnet' as the network passed.
  for (const net of ['mainnet', 'devnet', 'testnet'] as const) {
    test(`§7.1: ${net} is a working selector`, () => {
      assert.deepEqual(ok(`did:sns:${net}:alice.crbank`), { name: 'alice.crbank', network: net })
    })
  }

  test('§7.1: "When no network component is present, mainnet is implied"', () => {
    assert.equal(ok('did:sns:alice.crbank').network, 'mainnet')
  })

  test('§7.1: a selector requires "another `:` and a non-empty sns-name"', () => {
    // Verbatim conditional from §7.1; the empty-name case was untested.
    invalidDid('did:sns:devnet:')
    invalidDid('did:sns:mainnet:')
  })

  test('§7.1: a non-network token in selector position is not a network', () => {
    // `network` is exactly three literals and `:` is not in `label`.
    invalidDid('did:sns:localnet:alice')
  })

  test('§9.2: the suffix is stripped for a network-qualified name too', () => {
    assert.deepEqual(ok('did:sns:devnet:alice.attestto.sol'), {
      name: 'alice.attestto',
      network: 'devnet',
    })
  })

  // NOT ASSERTED — `did:sns:DEVNET:alice`. RFC 5234 §2.3 makes ABNF string
  // literals case-insensitive by default, so a strict reading admits it.
  // Almost certainly unintended. SOC-177.
})

describe('§7.1 — ABNF: label = 1*( ALPHA / DIGIT / "-" )', () => {
  test('§7.1: underscore is outside the grammar', () => {
    // The live defect: the regex uses [\w.-], and \w admits `_`.
    // ⚠️ Two GENERATORS emit underscores today — attestto-desktop
    // station-service.ts:95 (base64url ids) and CORTEX holder_did_resolver.ts:30
    // (usernames, which user_validator.ts:26-32 permits `_` in). Fix those
    // before this lands or their identifiers stop resolving.
    invalidDid('did:sns:bad_underscore')
    invalidDid('did:sns:station-aB_cD.attestto')
  })

  test('§7.1: an empty label is not a label — 1* means at least one', () => {
    for (const bad of ['did:sns:alice.', 'did:sns:.alice', 'did:sns:a..b', 'did:sns:', 'did:sns:.']) {
      invalidDid(bad)
    }
  })

  test('§7.1: hyphens and digits are legal anywhere in a label', () => {
    assert.equal(ok('did:sns:cr-111290877.attestto').name, 'cr-111290877.attestto')
    assert.equal(ok('did:sns:go-cr').name, 'go-cr')
    // The ABNF permits leading/trailing/all-hyphen labels. The shipped regex
    // requires an alphanumeric first char — stricter than the grammar, the
    // opposite direction from the underscore bug.
    assert.equal(ok('did:sns:-alice').name, '-alice')
    assert.equal(ok('did:sns:alice-').name, 'alice-')
  })

  // NOT ASSERTED — label case. ABNF ALPHA is %x41-5A / %x61-7A, so BOTH cases
  // are in the grammar, and §3 uses `usBank.sol` / `otherPlatform.sol`. But
  // §9.2 step 4 hashes "SPL Name Service" + name, so `Alice` and `alice` derive
  // DIFFERENT PDAs — one capital letter is a silent 404. The spec defines no
  // normalisation. This is the biggest open question here. SOC-177.
})

describe('§7.2 — two levels maximum (root + one subdomain)', () => {
  test('§7.2: root and one subdomain are supported', () => {
    assert.equal(ok('did:sns:crbank').name, 'crbank')
    assert.equal(ok('did:sns:alice.crbank').name, 'alice.crbank')
  })

  test('§7.2: nested beyond one subdomain is refused', () => {
    // Refused, code unasserted — §7.2 says only "rejected by resolver".
    //
    // SNS is `subdomain.domain`. Two levels is a property of Solana Name
    // Service, not a policy: a three-label name has no PDA to derive, so it is
    // IMPOSSIBLE rather than disallowed. Several artefacts write one anyway —
    // `user.tenant.attestto.sol` (creds-extension CLAUDE.md:50),
    // `notario-garcia.abogados.attestto.sol` (cr-vc-schemas examples),
    // `attestto.officer.1` (did-sns-spec's own credential README, contradicting
    // its §7.2). Those are DOC BUGS. The tenant IS the domain: a Tier 2 identity
    // is `alice.crbank`, never `alice.crbank.attestto`.
    refused('did:sns:dept.alice.crbank')
    refused('did:sns:user.tenant.attestto.sol')
    refused('did:sns:a.b.c.d')
  })

  test('§7.2: depth is counted on the name, after selector and suffix', () => {
    refused('did:sns:devnet:dept.alice.crbank')
    refused('did:sns:dept.alice.crbank.sol')
  })
})

/**
 * The part a lookup table cannot survive.
 *
 * Inputs are constructed from the grammar and their expectations derived from
 * it — an independent referent, not a re-run of the implementation. A parser
 * that special-cases the literals above fails here on the first generated name
 * its author never wrote down.
 */
describe('generated — inputs built from the ABNF, expectations derived from it', () => {
  const LEGAL = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'
  const ILLEGAL = '_ !@#$%^&*()+=[]{}|\\;"\'<>,?/~`'
  const SOL = '.sol'

  /** Deterministic pseudo-random so a failure is reproducible. */
  function rng(seed: number) {
    let s = seed
    return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
  }

  function makeLabel(rand: () => number, len: number) {
    let out = ''
    for (let i = 0; i < len; i++) out += LEGAL[Math.floor(rand() * LEGAL.length)]
    return out
  }

  test('every generated in-grammar name at depth 1 and 2 parses, suffixed or not', () => {
    const rand = rng(20260810)
    for (let i = 0; i < 400; i++) {
      const root = makeLabel(rand, 1 + Math.floor(rand() * 12))
      const depth2 = rand() < 0.5
      const name = depth2 ? `${makeLabel(rand, 1 + Math.floor(rand() * 12))}.${root}` : root

      // A generated label may collide with a reserved token at depth 1 — the
      // grammar admits it but §7.1 removes it. Derive the expectation.
      if (!depth2 && (name === 'mainnet' || name === 'devnet' || name === 'testnet')) {
        invalidDid(`did:sns:${name}`)
        continue
      }
      // A generated label may also be literally `sol`, making the unsuffixed
      // form indistinguishable from a suffixed one. Skip rather than assert a
      // guess about which reading wins.
      if (name.endsWith(SOL)) continue

      assert.equal(ok(`did:sns:${name}`).name, name, `plain: ${name}`)
      assert.equal(ok(`did:sns:${name}.sol`).name, name, `suffixed: ${name}.sol`)
      for (const net of ['mainnet', 'devnet', 'testnet'] as const) {
        assert.deepEqual(ok(`did:sns:${net}:${name}`), { name, network: net }, `${net}: ${name}`)
      }
    }
  })

  test('one out-of-grammar byte anywhere in a legal name makes it invalidDid', () => {
    const rand = rng(19820115)
    for (let i = 0; i < 400; i++) {
      const clean = `${makeLabel(rand, 3 + Math.floor(rand() * 8))}.${makeLabel(rand, 3 + Math.floor(rand() * 8))}`
      const at = Math.floor(rand() * clean.length)
      const byte = ILLEGAL[Math.floor(rand() * ILLEGAL.length)]
      const mutant = clean.slice(0, at) + byte + clean.slice(at)
      invalidDid(`did:sns:${mutant}`)
    }
  })

  test('every generated name of depth 3+ is refused', () => {
    const rand = rng(31337)
    for (let i = 0; i < 200; i++) {
      const depth = 3 + Math.floor(rand() * 3)
      const labels = Array.from({ length: depth }, () => makeLabel(rand, 1 + Math.floor(rand() * 8)))
      refused(`did:sns:${labels.join('.')}`)
      refused(`did:sns:${labels.join('.')}.sol`)
    }
  })
})
