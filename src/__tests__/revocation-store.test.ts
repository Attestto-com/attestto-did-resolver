/**
 * SOC-176 — checking a CA against the CRL that actually covers it.
 *
 * The pieces existed and were never joined: `manifest.certificates[].crlUrls`
 * comes from each certificate's CRL Distribution Points extension, so it names
 * the CRL where THAT certificate would appear if its issuer revoked it; and
 * `countries/<cc>/revocation.json` now carries the revoked serials from those
 * exact URLs. Nothing looked at either.
 *
 * The rules below all serve one property: **never report "not revoked" when the
 * truth is "not checked"**. Those are different answers and they were the same
 * bytes on the wire.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import {
  createRevocationLookup,
  type RevocationCrlEntry,
  type RevocationSnapshot,
} from '../revocation-store.js'

const CRL_A = 'http://ca.example/a.crl'
const CRL_B = 'http://ca.example/b.crl'
const HOUR = 3_600_000
const NOW = 1_760_000_000_000
const iso = (o: number) => new Date(NOW + o).toISOString()

function snapshot(crls: RevocationCrlEntry[]): RevocationSnapshot {
  return {
    country: 'XX',
    generatedAt: iso(-HOUR),
    snapshotExpiresAt: iso(HOUR),
    crls,
  }
}

const FRESH = {
  url: CRL_A,
  status: 'ok',
  thisUpdate: iso(-HOUR),
  nextUpdate: iso(HOUR),
  revokedCount: 2,
  revokedSerials: ['00ab', 'ff01'],
}

describe('a certificate is checked against the CRL that covers it', () => {
  test('a serial on the covering CRL is revoked', () => {
    const lookup = createRevocationLookup(snapshot([FRESH]))
    const r = lookup.check('00ab', [CRL_A], NOW)
    assert.equal(r.checked, true)
    assert.equal(r.revoked, true)
  })

  test('a serial absent from a FRESH covering CRL is genuinely not revoked', () => {
    const lookup = createRevocationLookup(snapshot([FRESH]))
    const r = lookup.check('1234', [CRL_A], NOW)
    assert.equal(r.checked, true)
    assert.equal(r.revoked, false)
  })

  test('serial comparison ignores case and separators', () => {
    // Manifests and CRLs disagree about formatting: `00:AB` vs `00ab`. Both
    // sides normalise, so neither has to know what the other did.
    const lookup = createRevocationLookup(snapshot([FRESH]))
    assert.equal(lookup.check('00:AB', [CRL_A], NOW).revoked, true)
    assert.equal(lookup.check('0x00AB', [CRL_A], NOW).revoked, true)
  })

  test('a CRL that does NOT cover the certificate is not consulted', () => {
    // The heart of it. Checking a certificate against someone else's revocation
    // list produces a confident answer about the wrong question — which is why
    // the SINPE end-entity lists must not be used for CA status.
    const lookup = createRevocationLookup(
      snapshot([{ ...FRESH, url: CRL_B, revokedSerials: ['00ab'] }]),
    )
    const r = lookup.check('00ab', [CRL_A], NOW)
    assert.equal(r.checked, false, 'no covering CRL was available')
    assert.equal(r.revoked, false)
    assert.equal(r.reason, 'no-covering-crl')
  })
})

describe('"not checked" is never reported as "not revoked"', () => {
  test('a certificate with no CRL distribution point is unchecked', () => {
    // Roots. A self-signed trust anchor is not CRL-revocable, and the trust
    // repo says so: "Roots carry no CRL (trust anchors are not CRL-revocable)".
    const lookup = createRevocationLookup(snapshot([FRESH]))
    const r = lookup.check('00ab', undefined, NOW)
    assert.equal(r.checked, false)
    assert.equal(r.reason, 'no-crl-distribution-point')
  })

  test('an unreachable CRL leaves the certificate unchecked', () => {
    // 117 of Italy's 154 CDP endpoints do not respond. Silence is not a
    // clean bill of health.
    const lookup = createRevocationLookup(
      snapshot([{ url: CRL_A, status: 'unreachable', error: 'ETIMEDOUT' }]),
    )
    const r = lookup.check('00ab', [CRL_A], NOW)
    assert.equal(r.checked, false)
    assert.equal(r.reason, 'crl-unreachable')
  })

  test('a CRL past its own nextUpdate leaves the certificate unchecked', () => {
    // Czechia has a CDP frozen at 2011, Chile two dead since the 2018 Symantec
    // distrust. A CRL past nextUpdate must not be relied upon: anything revoked
    // after it was issued is missing from it, so "absent" means nothing.
    const lookup = createRevocationLookup(
      snapshot([{ ...FRESH, nextUpdate: iso(-HOUR), revokedSerials: [] }]),
    )
    const r = lookup.check('1234', [CRL_A], NOW)
    assert.equal(r.checked, false)
    assert.equal(r.reason, 'crl-stale')
  })

  test('a stale CRL that DOES list the serial still reports revoked', () => {
    // Staleness invalidates absence, not presence. A revocation already
    // published does not un-happen because the CA stopped reissuing.
    const lookup = createRevocationLookup(
      snapshot([{ ...FRESH, nextUpdate: iso(-HOUR) }]),
    )
    const r = lookup.check('00ab', [CRL_A], NOW)
    assert.equal(r.revoked, true)
    assert.equal(r.checked, true)
  })

  test('no snapshot at all leaves everything unchecked', () => {
    const lookup = createRevocationLookup(null)
    const r = lookup.check('00ab', [CRL_A], NOW)
    assert.equal(r.checked, false)
    assert.equal(r.reason, 'no-snapshot')
  })

  test('one fresh covering CRL is enough even if a sibling is dead', () => {
    // CDPs are commonly listed in pairs for redundancy (crl1/crl2). One
    // responding is a successful check.
    const lookup = createRevocationLookup(
      snapshot([{ url: CRL_A, status: 'unreachable' }, { ...FRESH, url: CRL_B }]),
    )
    const r = lookup.check('1234', [CRL_A, CRL_B], NOW)
    assert.equal(r.checked, true)
    assert.equal(r.revoked, false)
  })
})
