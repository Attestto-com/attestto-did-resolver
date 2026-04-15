import type { DidResolutionResult } from './types.js';
import { parseDid } from './parser.js';
import { TrustRegistry } from './registry.js';
import { buildDidDocument } from './document.js';

/**
 * did:pki Resolver
 *
 * Resolves did:pki identifiers to W3C DID Documents by looking up
 * CA certificates in a trust registry and constructing the document
 * from the certificate data.
 */
export class DidPkiResolver {
  private registry: TrustRegistry;

  constructor(registry: TrustRegistry) {
    this.registry = registry;
  }

  /**
   * Resolve a did:pki identifier to a DID Resolution Result.
   * Implements the resolution algorithm from spec §6.
   */
  resolve(did: string): DidResolutionResult {
    // Step 1: Parse the DID string
    const parsed = parseDid(did);
    if (!parsed) {
      return this.error('invalidDid', `Invalid did:pki identifier: ${did}`);
    }

    // Step 2: Validate country code (basic — 2 lowercase alpha)
    if (!/^[a-z]{2}$/.test(parsed.countryCode)) {
      return this.error('invalidDid', `Invalid country code: ${parsed.countryCode}`);
    }

    // Step 3: Look up in trust registry
    const entries = this.registry.lookup(parsed.countryCode, parsed.caPath);
    if (entries.length === 0) {
      return this.error('notFound', `No CA found for: ${did}`);
    }

    // Step 4: Filter by generation if specified
    let filteredEntries = entries;
    if (parsed.generation) {
      filteredEntries = entries.filter(e => {
        const year = new Date(e.cert.validFrom).getFullYear().toString();
        return year === parsed.generation;
      });
      if (filteredEntries.length === 0) {
        return this.error('notFound', `No generation ${parsed.generation} found for: ${did}`);
      }
    }

    // Step 5-8: Build DID Document
    try {
      const pemContents = new Map<string, string>();
      for (const entry of filteredEntries) {
        pemContents.set(entry.cert.file, this.registry.readPem(entry));
      }

      const { document, metadata } = buildDidDocument(filteredEntries, pemContents);

      return {
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: document,
        didDocumentMetadata: metadata,
        didResolutionMetadata: {
          contentType: 'application/did+json',
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.error('internalError', message);
    }
  }

  /** List all resolvable DIDs in this registry */
  listDids(): string[] {
    return this.registry.getAllDids();
  }

  private error(code: string, message: string): DidResolutionResult {
    return {
      '@context': 'https://w3id.org/did-resolution/v1',
      didDocument: null,
      didDocumentMetadata: {
        created: '',
        updated: '',
        versionId: '',
      },
      didResolutionMetadata: {
        contentType: 'application/did+json',
        error: code,
        message,
      },
    };
  }
}
