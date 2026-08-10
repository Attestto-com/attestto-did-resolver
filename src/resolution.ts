/**
 * Shared DID Resolution result shape and HTTP status mapping.
 *
 * Both methods on this server built their own error results and disagreed:
 * `pki-resolver.ts` emitted `message`, `sns-resolver.ts` emitted
 * `errorMessage`. A consumer could not read a failure generically from a
 * resolver that advertises DIF Universal Resolver conformance. One definition,
 * used by both, removes the class of defect rather than the instance.
 */
import type { DidResolutionResult } from './types.js'

/**
 * §9.2's error table, as HTTP.
 *
 *   invalidDid    400   malformed syntax, wrong prefix, invalid characters
 *   notFound      404   not registered / no account
 *   deactivated   200   a deactivated DID still resolves
 *   internalError 500   RPC failure or resolver error
 *
 * Previously `internalError` was answered with **200** plus `retriable: true`
 * and `Retry-After: 0`. The intent — invite an immediate retry after a
 * transient upstream failure — was reasonable; the encoding was not. Every DIF
 * consumer in this workspace gates on `res.ok`, so a dead Solana RPC or an
 * unreadable trust store was read as a successful resolution of a null
 * document. Retry guidance goes in `Retry-After`, which is exactly what that
 * header is for, and the status tells the truth.
 *
 * `deactivated` had no case at all and fell through to 500.
 */
export function statusForResolution(error: string | undefined): number {
  switch (error) {
    case undefined:
      return 200
    case 'deactivated':
      return 200
    case 'invalidDid':
      return 400
    case 'notFound':
      return 404
    case 'internalError':
      return 500
    default:
      // An unrecognised code is a resolver bug, not a client error. Never 200:
      // a status a consumer treats as success must never carry a null document.
      return 500
  }
}

/**
 * A DID Resolution error result.
 *
 * Three things the previous `did:pki` version got wrong, all visible in a live
 * response:
 *
 *   - `message` instead of `errorMessage`. Not a DID Resolution property.
 *   - `didDocumentMetadata: { created: '', updated: '', versionId: '' }`.
 *     `created` and `updated` are XMLSchema dateTime, and `""` is not a value
 *     of that type — the result was invalid, not merely unhelpful. On a failure
 *     the correct value is `{}`.
 *   - `contentType` set while `didDocument` is null. It describes a returned
 *     representation, and there is none; the value it declared
 *     (`application/did+json`) also contradicted the header the server wrote
 *     (`application/did+ld+json`).
 */
export function resolutionError(error: string, errorMessage: string): DidResolutionResult {
  return {
    '@context': 'https://w3id.org/did-resolution/v1',
    didDocument: null,
    didDocumentMetadata: {},
    didResolutionMetadata: { error, errorMessage },
  }
}
