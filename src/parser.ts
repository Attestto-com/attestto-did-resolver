import type { ParsedDid } from './types.js';

const DID_PKI_REGEX = /^did:pki:([a-z]{2}):(.+)$/;
const SEGMENT_REGEX = /^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/;
const GENERATION_REGEX = /^\d{4}$/;

/**
 * Parse a did:pki identifier into its components.
 *
 * @returns ParsedDid or null if invalid
 */
export function parseDid(did: string): ParsedDid | null {
  const match = did.match(DID_PKI_REGEX);
  if (!match) return null;

  const countryCode = match[1];
  const pathStr = match[2];
  const segments = pathStr.split(':');

  if (segments.length === 0 || segments.some(s => s.length === 0)) {
    return null;
  }

  // Validate each segment
  for (const seg of segments) {
    if (!SEGMENT_REGEX.test(seg)) {
      return null;
    }
  }

  // Check if last segment is a generation year
  const lastSegment = segments[segments.length - 1];
  let generation: string | undefined;
  let caPath: string[];

  if (GENERATION_REGEX.test(lastSegment) && segments.length > 1) {
    generation = lastSegment;
    caPath = segments.slice(0, -1);
  } else {
    caPath = segments;
  }

  return {
    method: 'pki',
    countryCode,
    caPath,
    generation,
  };
}

/** Reconstruct a DID string from parsed components */
export function formatDid(parsed: ParsedDid): string {
  const parts = ['did', 'pki', parsed.countryCode, ...parsed.caPath];
  if (parsed.generation) {
    parts.push(parsed.generation);
  }
  return parts.join(':');
}
