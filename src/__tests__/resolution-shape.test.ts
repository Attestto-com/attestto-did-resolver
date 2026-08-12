/**
 * SOC-176 — DID Resolution conformance of the error result and its HTTP status.
 *
 * Two methods share this server and disagreed about the shape of a failure, so
 * a client could not read one generically. And a total infrastructure failure
 * was reported as HTTP 200.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { statusForResolution, resolutionError } from '../resolution.js'

describe('§9.2 — HTTP status follows the resolution error', () => {
  test('a successful resolution is 200', () => {
    assert.equal(statusForResolution(undefined), 200)
  })

  test('invalidDid is 400', () => {
    assert.equal(statusForResolution('invalidDid'), 400)
  })

  test('notFound is 404', () => {
    assert.equal(statusForResolution('notFound'), 404)
  })

  test('deactivated is 200 — a deactivated DID still resolves', () => {
    // §9.2's table says 200, and §9.4 returns a result with
    // `didDocumentMetadata.deactivated = true`. The old map had no case for it,
    // so it fell through to 500 — a retired identity reported as a server bug.
    assert.equal(statusForResolution('deactivated'), 200)
  })

  test('internalError is 500, not 200', () => {
    // It was 200 with `didDocument: null` and `retriable: true`. Every DIF
    // consumer in this workspace gates on `res.ok` — attestto-verify,
    // id-wallet-adapter, wallet-identity-resolver, attestto-desktop — so a
    // dead Solana RPC or an unreadable trust store read as a SUCCESSFUL
    // resolution of a null document. A retry hint belongs in a header, not in
    // a success code.
    assert.equal(statusForResolution('internalError'), 500)
  })

  test('an unrecognised error code does not become a success', () => {
    assert.equal(statusForResolution('somethingNew'), 500)
  })
})

describe('§9.2 — the error result shape is the same for both methods', () => {
  test('the message field is `errorMessage`, per DID Resolution', () => {
    // `pki-resolver.ts` emitted `message` while `sns-resolver.ts` on the SAME
    // server emitted `errorMessage`, so no client could read either
    // generically.
    const result = resolutionError('notFound', 'No CA found for: did:pki:zz:nope')
    assert.equal(result.didResolutionMetadata.errorMessage, 'No CA found for: did:pki:zz:nope')
    assert.equal(
      (result.didResolutionMetadata as Record<string, unknown>).message,
      undefined,
      '`message` is not a DID Resolution property',
    )
  })

  test('didDocumentMetadata is empty on a failure, not filled with empty strings', () => {
    // It carried `{created: '', updated: '', versionId: ''}`. `created` and
    // `updated` are XMLSchema dateTime — `""` is not a valid value of that
    // type, so the result was not just unhelpful but invalid.
    const result = resolutionError('notFound', 'x')
    assert.deepEqual(result.didDocumentMetadata, {})
  })

  test('contentType is absent when there is no document to describe', () => {
    // `contentType` describes the returned representation. With
    // `didDocument: null` there is no representation, and the value it declared
    // (`application/did+json`) contradicted the header the server actually
    // wrote (`application/did+ld+json`).
    const result = resolutionError('invalidDid', 'x')
    assert.equal(result.didResolutionMetadata.contentType, undefined)
  })

  test('the result still carries the resolution context and a null document', () => {
    const result = resolutionError('internalError', 'boom')
    assert.equal(result['@context'], 'https://w3id.org/did-resolution/v1')
    assert.equal(result.didDocument, null)
    assert.equal(result.didResolutionMetadata.error, 'internalError')
  })
})
