/**
 * CR Firma Digital (SINPE) CRL-based revocation service.
 *
 * Browsers on verify.attestto.com cannot fetch the BCCR CRLs directly: they are
 * plain HTTP (mixed-content blocked) and serve no CORS headers. This service
 * fetches them server-side, verifies each CRL signature against the CA cert the
 * resolver already bundles in the trust store, caches the parsed result, and
 * exposes it as CORS-enabled JSON.
 *
 * Privacy: the endpoint takes NO certificate serial. It returns the full revoked
 * list so the client checks locally and never reveals which cert it is verifying.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseCrl, verifyCrlSignature, subjectKeyId, type ParsedCrl } from './crl-parser.js';

/** Supported CR CA identifiers. */
export type CrCa = 'sinpe-persona-fisica' | 'sinpe-persona-juridica';

interface CaConfig {
  /** Current-era CRL URLs (v2(2) and v2(3)); both are fetched and merged. */
  crlUrls: string[];
  /** Candidate bundled CA cert PEM filenames (relative to countries/cr/current/). */
  caCertFiles: string[];
}

const BASE = 'http://fdi.sinpe.fi.cr/repositorio';

const CA_CONFIG: Record<CrCa, CaConfig> = {
  'sinpe-persona-fisica': {
    crlUrls: [
      `${BASE}/CA%20SINPE%20-%20PERSONA%20FISICA%20v2(2).crl`,
      `${BASE}/CA%20SINPE%20-%20PERSONA%20FISICA%20v2(3).crl`,
    ],
    caCertFiles: [
      'CA SINPE - PERSONA FISICA v2 (2023).pem',
      'CA SINPE - PERSONA FISICA v2.pem',
    ],
  },
  'sinpe-persona-juridica': {
    crlUrls: [
      `${BASE}/CA%20SINPE%20-%20PERSONA%20JURIDICA%20v2(2).crl`,
      `${BASE}/CA%20SINPE%20-%20PERSONA%20JURIDICA%20v2(3).crl`,
    ],
    caCertFiles: ['CA SINPE - PERSONA JURIDICA v2.pem'],
  },
};

/** JSON response body for a successful revocation lookup. */
export interface RevocationResult {
  ca: CrCa;
  issuer: string;
  thisUpdate: string;
  nextUpdate: string | null;
  stale: boolean;
  signatureVerified: boolean;
  revokedSerials: string[];
}

/** Minimum time a cached result is reused, even if nextUpdate is sooner. */
const MIN_CACHE_MS = 60 * 60 * 1000; // 1 hour safety floor to avoid hammering BCCR
/** Fallback re-fetch interval when a CRL omits nextUpdate. */
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

interface CacheEntry {
  result: RevocationResult;
  /** Epoch ms before which the cached result is served without re-fetching. */
  reuseUntil: number;
}

/** Injectable fetcher so tests can mock the upstream without network access. */
export type CrlFetcher = (url: string) => Promise<Buffer>;

const defaultFetcher: CrlFetcher = async (url) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Upstream ${res.status} for ${url}`);
  const ab = await res.arrayBuffer();
  return Buffer.from(ab);
};

export class CrlRevocationService {
  private cache = new Map<CrCa, CacheEntry>();
  private currentDir: string;
  private fetcher: CrlFetcher;
  /** SKI (hex) → CA cert PEM, built lazily from bundled certs for AKI matching. */
  private caCertsBySki = new Map<string, string>();
  private caCertPems: string[] = [];
  private certsLoaded = false;

  constructor(trustStorePath: string, fetcher: CrlFetcher = defaultFetcher) {
    this.currentDir = join(resolve(trustStorePath), 'cr', 'current');
    this.fetcher = fetcher;
  }

  static isSupported(ca: string): ca is CrCa {
    return ca === 'sinpe-persona-fisica' || ca === 'sinpe-persona-juridica';
  }

  /**
   * Resolve revocation status for a CA, using the in-memory cache when fresh.
   * Throws if all upstream CRL fetches fail.
   */
  async getRevocation(ca: CrCa, now: number = Date.now()): Promise<RevocationResult> {
    const cached = this.cache.get(ca);
    if (cached && now < cached.reuseUntil) {
      return cached.result;
    }

    const result = await this.fetchAndBuild(ca, now);

    // Cache until the earliest nextUpdate, but never less than the safety floor.
    let reuseUntil = now + MIN_CACHE_MS;
    if (result.nextUpdate) {
      const nextMs = new Date(result.nextUpdate).getTime();
      reuseUntil = Math.max(nextMs, now + MIN_CACHE_MS);
    } else {
      reuseUntil = now + DEFAULT_TTL_MS;
    }
    this.cache.set(ca, { result, reuseUntil });
    return result;
  }

  private loadCaCerts(ca: CrCa): string[] {
    const pems: string[] = [];
    for (const file of CA_CONFIG[ca].caCertFiles) {
      const path = join(this.currentDir, file);
      if (existsSync(path)) {
        try {
          const pem = readFileSync(path, 'utf-8');
          pems.push(pem);
          const ski = subjectKeyId(pem);
          if (ski) this.caCertsBySki.set(ski, pem);
        } catch {
          // Skip unreadable cert; verification will simply fail for it.
        }
      }
    }
    return pems;
  }

  /**
   * Verify one CRL against the correct bundled CA cert. Prefers matching the
   * CRL's Authority Key Identifier to a bundled cert's Subject Key Identifier;
   * falls back to trying every candidate cert for this CA.
   */
  private verifyOne(crl: ParsedCrl, candidatePems: string[]): boolean {
    if (crl.authorityKeyId) {
      const match = this.caCertsBySki.get(crl.authorityKeyId);
      if (match) return verifyCrlSignature(crl, match);
      // AKI present but no bundled cert matches → cannot verify.
      return false;
    }
    return candidatePems.some((pem) => verifyCrlSignature(crl, pem));
  }

  private async fetchAndBuild(ca: CrCa, now: number): Promise<RevocationResult> {
    const cfg = CA_CONFIG[ca];
    const candidatePems = this.loadCaCerts(ca);
    this.certsLoaded = true;

    const parsed: ParsedCrl[] = [];
    const errors: string[] = [];
    for (const url of cfg.crlUrls) {
      try {
        const der = await this.fetcher(url);
        parsed.push(parseCrl(der));
      } catch (err) {
        errors.push(err instanceof Error ? err.message : String(err));
      }
    }

    if (parsed.length === 0) {
      throw new Error(
        `All CRL fetches failed for ${ca}: ${errors.join('; ') || 'unknown error'}`,
      );
    }

    // Merge revoked serials (dedup), earliest nextUpdate, latest thisUpdate.
    const serialSet = new Set<string>();
    let issuer = '';
    let thisUpdate = '';
    let earliestNext: string | null = null;
    let allVerified = true;

    for (const crl of parsed) {
      for (const s of crl.revokedSerials) serialSet.add(s);
      if (!issuer) issuer = crl.issuer;
      if (!thisUpdate || crl.thisUpdate > thisUpdate) thisUpdate = crl.thisUpdate;
      if (crl.nextUpdate) {
        if (earliestNext === null || crl.nextUpdate < earliestNext) earliestNext = crl.nextUpdate;
      }
      if (!this.verifyOne(crl, candidatePems)) allVerified = false;
    }

    // If a configured CRL failed to fetch, we cannot claim a complete verified view.
    if (errors.length > 0) allVerified = false;

    const stale = earliestNext !== null && now > new Date(earliestNext).getTime();

    return {
      ca,
      issuer,
      thisUpdate,
      nextUpdate: earliestNext,
      stale,
      signatureVerified: allVerified,
      revokedSerials: [...serialSet].sort(),
    };
  }
}
