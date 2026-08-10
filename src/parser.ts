import type { ParsedDid } from './types.js';

const DID_PKI_REGEX = /^did:pki:([a-zA-Z]{2}):(.+)$/;
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

  // ISO 3166 alpha-2 is conventionally case-insensitive, and `registry.lookup()`
  // already lowercases defensively — so rejecting `did:pki:CR:…` was the
  // parser's own doing, and rejected nothing the registry could not serve.
  const countryCode = match[1].toLowerCase();
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

// ── DID URLs ─────────────────────────────────────────────────────────────────

/**
 * A DID URL split into its parts.
 *
 * Per DID Core, a DID URL is `did:method:id` optionally followed by
 * `path-abempty`, `?query` and `#fragment`, in that order. A resolver resolves
 * the DID and applies the remainder — `versionId` and `versionTime` are defined
 * resolution options, not decoration.
 */
export interface ParsedDidUrl {
  /** The bare DID, with path/query/fragment removed. */
  did: string
  /** Leading-slash path, if present. */
  path?: string
  query?: URLSearchParams
  /** Fragment WITHOUT the leading `#`. */
  fragment?: string
}

/**
 * Split a DID URL into its components.
 *
 * The resolver used to hand the whole string to `parseDid`, so
 * `did:pki:cr:raiz-nacional#key-1` — the shape of a `kid` read straight out of
 * a JWS header, and exactly what `vc-sdk`'s verifier produces — came back
 * `invalidDid`. Splitting here does NOT weaken validation: the DID that remains
 * is still parsed and rejected on its own merits.
 *
 * Returns null when the input is not a DID at all, or when a component is
 * present but empty (`…#` names no fragment).
 */
export function parseDidUrl(input: string): ParsedDidUrl | null {
  if (!input.startsWith('did:')) return null

  let rest = input
  let fragment: string | undefined
  let query: URLSearchParams | undefined
  let path: string | undefined

  // Order matters: fragment is last in the URL, so it comes off first.
  const hash = rest.indexOf('#')
  if (hash !== -1) {
    fragment = rest.slice(hash + 1)
    rest = rest.slice(0, hash)
    if (fragment.length === 0) return null
  }

  const q = rest.indexOf('?')
  if (q !== -1) {
    const raw = rest.slice(q + 1)
    rest = rest.slice(0, q)
    if (raw.length === 0) return null
    query = new URLSearchParams(raw)
  }

  const slash = rest.indexOf('/')
  if (slash !== -1) {
    path = rest.slice(slash)
    rest = rest.slice(0, slash)
    if (path.length <= 1) return null
  }

  if (rest.length === 0) return null
  return { did: rest, path, query, fragment }
}
