/**
 * CA revocation lookup, from the trust directory's own snapshot.
 *
 * `countries/<cc>/revocation.json` in `@attestto/trust` records, per CRL URL,
 * the serials that CRL revokes and when it was issued. `manifest.certificates[]
 * .crlUrls` comes from each certificate's CRL Distribution Points extension, so
 * it names precisely the CRL where THAT certificate would appear if its issuer
 * revoked it.
 *
 * Both halves existed and nothing joined them, so `did:pki` reported a
 * revocation status it never determined.
 *
 * ── The one property this module protects ──────────────────────────────────
 *
 * **"Not checked" is never reported as "not revoked".** They are different
 * answers, and before this they were the same bytes on the wire — which is what
 * made attestto-verify's revocation branch vacuous. Every path returns
 * `checked` alongside `revoked`, and a caller that needs assurance must read
 * both.
 */

export interface RevocationCrlEntry {
  url: string
  status: string
  thisUpdate?: string | null
  nextUpdate?: string | null
  revokedCount?: number
  revokedSerials?: string[]
}

export interface RevocationSnapshot {
  country: string
  generatedAt: string
  snapshotExpiresAt: string | null
  crls: RevocationCrlEntry[]
}

export type RevocationReason =
  /** No `revocation.json` shipped with this trust store. */
  | 'no-snapshot'
  /** The certificate carries no CRL Distribution Point — e.g. a self-signed root. */
  | 'no-crl-distribution-point'
  /** The certificate names CRLs, but none of them is in the snapshot. */
  | 'no-covering-crl'
  /** Every covering CRL failed to fetch. */
  | 'crl-unreachable'
  /** Every covering CRL is past its own nextUpdate. */
  | 'crl-stale'
  /** A covering CRL was read. */
  | 'checked'

export interface RevocationVerdict {
  /** Whether a usable CRL was consulted. False means UNKNOWN, not "good". */
  checked: boolean
  revoked: boolean
  reason: RevocationReason
  /** The CRL that produced the verdict, when there was one. */
  source?: string
}

export interface RevocationLookup {
  check(serialNumber: string, crlUrls: string[] | undefined, now?: number): RevocationVerdict
}

/**
 * Lowercase hex, separators stripped.
 *
 * Manifests, CRLs and human-pasted values disagree about formatting — `00:AB`,
 * `0x00ab`, `00ab` are the same serial. Both sides normalise so neither has to
 * know what the other did.
 */
function normalizeSerial(serial: string): string {
  return serial.replace(/^0x/i, '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
}

export function createRevocationLookup(snapshot: RevocationSnapshot | null): RevocationLookup {
  if (!snapshot) {
    return { check: () => ({ checked: false, revoked: false, reason: 'no-snapshot' }) }
  }

  const byUrl = new Map<string, RevocationCrlEntry>()
  for (const crl of snapshot.crls) byUrl.set(crl.url, crl)

  return {
    check(serialNumber, crlUrls, now = Date.now()): RevocationVerdict {
      if (!crlUrls || crlUrls.length === 0) {
        // A self-signed trust anchor is not CRL-revocable, and the trust repo
        // says so explicitly. Unchecked here is correct, not a gap to close.
        return { checked: false, revoked: false, reason: 'no-crl-distribution-point' }
      }

      const covering = crlUrls.map((u) => byUrl.get(u)).filter((c): c is RevocationCrlEntry => !!c)
      if (covering.length === 0) {
        // The certificate names CRLs we have no data for. Consulting a
        // NON-covering CRL instead would produce a confident answer to the
        // wrong question — exactly the mistake of checking a CA against the
        // end-entity list its own subscribers appear on.
        return { checked: false, revoked: false, reason: 'no-covering-crl' }
      }

      const target = normalizeSerial(serialNumber)

      // Presence first, and deliberately before any freshness test: staleness
      // invalidates ABSENCE, not presence. A revocation already published does
      // not un-happen because the CA stopped reissuing its CRL.
      for (const crl of covering) {
        if (crl.status !== 'ok' || !crl.revokedSerials) continue
        if (crl.revokedSerials.some((s) => normalizeSerial(s) === target)) {
          return { checked: true, revoked: true, reason: 'checked', source: crl.url }
        }
      }

      // Absence only means something from a CRL that is both reachable and
      // current. Anything revoked after a stale CRL was issued is missing from
      // it, so "not listed" carries no information.
      const usable = covering.filter(
        (c) =>
          c.status === 'ok' &&
          c.revokedSerials !== undefined &&
          (!c.nextUpdate || Date.parse(c.nextUpdate) > now),
      )
      if (usable.length > 0) {
        return { checked: true, revoked: false, reason: 'checked', source: usable[0].url }
      }

      // Report WHY the check could not be made, so a consumer can tell a dead
      // endpoint from a frozen one. 117 of Italy's 154 CDPs do not respond;
      // Czechia has one frozen at 2011. Those are different problems.
      const reachable = covering.filter((c) => c.status === 'ok')
      return {
        checked: false,
        revoked: false,
        reason: reachable.length === 0 ? 'crl-unreachable' : 'crl-stale',
      }
    },
  }
}
