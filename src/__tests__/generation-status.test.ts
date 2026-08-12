/**
 * SOC-176 — `did:pki` reports a revocation status it never checks.
 *
 * `'revoked'` appears exactly twice in the whole did:pki path: the type union
 * (`types.ts`) and a predicate (`document.ts`). NOTHING produces it —
 * `buildDidDocument` never consults any revocation source. So a
 * revoked-but-unexpired CA resolved as fully active, and
 * `attestto-verify/src/composables/pki-resolver.ts`, which branches over
 * `'active' | 'revoked' | 'expired'`, has a branch that can never fire. A
 * control that exists, looks like it covers the invariant, and cannot.
 *
 * The tempting fix is wrong: the CRL service this process already runs covers
 * `sinpe-persona-fisica` / `sinpe-persona-juridica`, which are END-ENTITY
 * CRLs — the certificates those CAs issue to people and companies. The trust
 * store holds the CAs THEMSELVES. Checking a CA against its own subscribers'
 * revocation list would be a control that looks even more convincing and
 * covers even less.
 *
 * So the fix is honesty, not a wire-up: report that revocation was not checked,
 * and never emit a status the resolver did not determine. That converts a
 * vacuous control into a visible gap a consumer can act on — the same move as
 * `degraded` in §9.2.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { getGenerationStatus } from '../document.js'

const HOUR = 3_600_000

function iso(offsetMs: number) {
  return new Date(1_760_000_000_000 + offsetMs).toISOString()
}
const NOW = new Date(1_760_000_000_000)

describe('validity-window status is determined, not guessed', () => {
  test('a current certificate is active', () => {
    assert.equal(getGenerationStatus(iso(-HOUR), iso(HOUR), NOW), 'active')
  })

  test('a past certificate is expired', () => {
    assert.equal(getGenerationStatus(iso(-2 * HOUR), iso(-HOUR), NOW), 'expired')
  })

  test('a certificate whose notBefore is in the future is NOT active', () => {
    // The old code returned 'active' with the comment "not yet valid but still
    // active in registry". A CA that cannot yet sign anything is not in
    // service, and reporting it as active is indistinguishable from one that
    // is — a verifier has no way to tell them apart.
    assert.equal(getGenerationStatus(iso(HOUR), iso(2 * HOUR), NOW), 'not-yet-valid')
  })

  test('the boundaries are inclusive of the validity window', () => {
    assert.equal(getGenerationStatus(iso(0), iso(HOUR), NOW), 'active')
    assert.equal(getGenerationStatus(iso(-HOUR), iso(0), NOW), 'active')
  })

  test('an unparseable date is not silently treated as valid', () => {
    // `new Date('nonsense')` is Invalid Date, and every comparison against it
    // is false — so the old chain fell through to `return 'active'`. A cert
    // whose dates cannot be read is the one case that must never read as
    // in-service.
    assert.equal(getGenerationStatus('nonsense', iso(HOUR), NOW), 'unknown')
    assert.equal(getGenerationStatus(iso(-HOUR), 'nonsense', NOW), 'unknown')
  })
})

describe('revocation is never claimed without a check', () => {
  test('the status function cannot return "revoked"', () => {
    // It has no revocation input, so it must not be able to produce the value.
    // Making that impossible in the type is what stops a future edit from
    // quietly reintroducing an unchecked claim.
    const statuses = [
      getGenerationStatus(iso(-HOUR), iso(HOUR), NOW),
      getGenerationStatus(iso(-2 * HOUR), iso(-HOUR), NOW),
      getGenerationStatus(iso(HOUR), iso(2 * HOUR), NOW),
    ]
    for (const s of statuses) {
      assert.notEqual(s, 'revoked', 'revocation was never checked, so it cannot be reported')
    }
  })
})
