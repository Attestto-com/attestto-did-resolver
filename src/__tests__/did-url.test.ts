/**
 * SOC-176 — a resolver must accept a DID URL, not just a bare DID.
 *
 * Per DID Core / DID Resolution, a DID URL is `did:method:id` optionally
 * followed by a path, a query and a fragment. A resolver dereferences the DID
 * and applies the rest; `versionId` and `versionTime` are DEFINED resolution
 * options, and §9.3 of the sns spec explicitly contemplates `versionTime`.
 *
 * `did:pki` rejected all of it as `invalidDid`, which matters because the most
 * natural thing a consumer holds is the `kid` it read out of a JWS header —
 * `did:pki:cr:sinpe:persona-fisica#key-1` — which is exactly the shape
 * `vc-sdk/src/verifier.ts:191` produces. Same class as the `.sol` bug in
 * SOC-171: an identifier the whole ecosystem writes, rejected by the parser.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { parseDid, parseDidUrl } from '../parser.js'

describe('DID URL components are parsed off, not rejected', () => {
  const BARE = 'did:pki:cr:raiz-nacional'

  test('a fragment is separated from the DID', () => {
    const url = parseDidUrl(`${BARE}#key-1`)
    assert.ok(url, 'a kid read from a JWS header must resolve')
    assert.equal(url.did, BARE)
    assert.equal(url.fragment, 'key-1')
  })

  test('a query is separated, and its parameters are available', () => {
    const url = parseDidUrl(`${BARE}?versionId=abc123`)
    assert.ok(url)
    assert.equal(url.did, BARE)
    assert.equal(url.query?.get('versionId'), 'abc123')
  })

  test('a path is separated', () => {
    const url = parseDidUrl(`${BARE}/whois`)
    assert.ok(url)
    assert.equal(url.did, BARE)
    assert.equal(url.path, '/whois')
  })

  test('all three together, in spec order: path, then query, then fragment', () => {
    const url = parseDidUrl(`${BARE}/whois?versionTime=2026-01-01T00:00:00Z#key-1`)
    assert.ok(url)
    assert.equal(url.did, BARE)
    assert.equal(url.path, '/whois')
    assert.equal(url.query?.get('versionTime'), '2026-01-01T00:00:00Z')
    assert.equal(url.fragment, 'key-1')
  })

  test('a bare DID has no path, query or fragment', () => {
    const url = parseDidUrl(BARE)
    assert.ok(url)
    assert.equal(url.did, BARE)
    assert.equal(url.path, undefined)
    assert.equal(url.query, undefined)
    assert.equal(url.fragment, undefined)
  })

  test('the DID inside a DID URL still parses into components', () => {
    const url = parseDidUrl('did:pki:cr:sinpe:persona-fisica#key-1')
    assert.ok(url)
    const parsed = parseDid(url.did)
    assert.ok(parsed, 'the bare DID must be resolvable')
    assert.equal(parsed.countryCode, 'cr')
    assert.deepEqual(parsed.caPath, ['sinpe', 'persona-fisica'])
  })

  test('a fragment does not smuggle an invalid DID through', () => {
    // Stripping the fragment must not become a way to launder a malformed DID.
    assert.equal(parseDid('did:pki:cr:BAD_SEGMENT'), null)
    const url = parseDidUrl('did:pki:cr:BAD_SEGMENT#key-1')
    assert.ok(url)
    assert.equal(parseDid(url.did), null, 'the DID is still invalid once the fragment is off')
  })

  test('an empty component is not silently accepted', () => {
    assert.equal(parseDidUrl('did:pki:cr:raiz-nacional#'), null)
    assert.equal(parseDidUrl('#key-1'), null)
    assert.equal(parseDidUrl(''), null)
  })

  test('a non-DID string is refused', () => {
    assert.equal(parseDidUrl('https://example.org/#frag'), null)
    assert.equal(parseDidUrl('not-a-did'), null)
  })
})

describe('country code case', () => {
  test('an uppercase country code is accepted and normalised', () => {
    // `registry.lookup()` already lowercases defensively, so the rejection was
    // purely the parser's. DID methods are case-sensitive in the method-specific
    // id, but an ISO 3166 alpha-2 code is conventionally case-insensitive and
    // the registry treats it that way.
    const parsed = parseDid('did:pki:CR:raiz-nacional')
    assert.ok(parsed, 'uppercase country codes were rejected outright')
    assert.equal(parsed.countryCode, 'cr')
  })
})
