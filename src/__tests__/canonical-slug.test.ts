/**
 * ATT-1070 — did:pki canonical slug + resolution round-trip.
 *
 * Root cause fixed here: the resolver re-derives each cert's DID at registry
 * load and matches resolution by `cc:pathKey`. The old `SEPARATOR_PATTERNS`
 * split a CN on mid-string " - " / " / " into SEPARATE path segments, so
 * `AC CAMERFIRMA FOR LEGAL PERSONS - 2016` produced a stray trailing `:2016`
 * segment; a client that folded the year to `-2016` then missed (notFound).
 *
 * The canonical slug rule (normalize.ts) now folds every non-idchar run into a
 * SINGLE hyphen, so a CN yields at most one path segment (org + one CN segment).
 * Generation-grouping (multiple certs → one DID with multiple verificationMethod
 * entries) is preserved and MUST NOT change.
 *
 * The round-trip test loads the real trust store and asserts that for EVERY
 * entry the registry builds, resolving its derived DID returns it — the tripwire
 * this bug slipped through.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveDid } from '../normalize.js';
import { parseDid } from '../parser.js';
import { TrustRegistry } from '../registry.js';
import { DidPkiResolver } from '../pki-resolver.js';

/** parser.ts segment grammar — every generated segment must satisfy this. */
const SEGMENT_REGEX = /^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/;

/**
 * Locate a trust store: prefer the sibling `../attestto-trust/countries`
 * (full set incl. Camerfirma/ATOS/CIE), fall back to the bundled fixture.
 */
function findTrustStore(): string | null {
  const here = fileURLToPath(new URL('.', import.meta.url));
  const candidates = [
    resolve(here, '../../../attestto-trust/countries'),
    resolve(here, '../../trust-store/countries'),
  ];
  return candidates.find(p => existsSync(p)) ?? null;
}

// --- Repro regressions -----------------------------------------------------

test('ATT-1070 repro: Camerfirma folds "- 2016" into ONE segment', () => {
  const did = deriveDid(
    'es',
    'AC CAMERFIRMA FOR LEGAL PERSONS - 2016',
    'AC CAMERFIRMA S.A.',
  );
  assert.equal(did, 'did:pki:es:ac-camerfirma:camerfirma-for-legal-persons-2016');
  // Exactly org + one CN segment — no stray trailing `:2016`.
  assert.equal(did.split(':').length, 5); // did pki es <org> <ca>
});

test('ATT-1070 repro: ATOS keeps sub-CA discriminator folded (hba-qca1)', () => {
  const did = deriveDid('de', 'ATOS.HBA-qCA1', 'Atos Information Technology GmbH');
  assert.equal(did, 'did:pki:de:atos-information-technology:hba-qca1');
});

// --- Whole-registry round-trip (the tripwire) ------------------------------

test('ATT-1070 round-trip: every registry DID resolves to itself', () => {
  const store = findTrustStore();
  assert.ok(store, 'no trust store found (sibling attestto-trust or local fixture)');

  const registry = new TrustRegistry(store);
  registry.load();
  const resolver = new DidPkiResolver(registry);

  const dids = resolver.listDids();
  assert.ok(dids.length > 0, 'registry indexed zero DIDs');

  const failures: string[] = [];
  for (const did of dids) {
    // 1. The derived DID must parse (valid method-specific-id / charset).
    const parsed = parseDid(did);
    if (!parsed) {
      failures.push(`${did} :: does not parse`);
      continue;
    }
    // 2. Every segment must satisfy the parser grammar (no stray punctuation).
    for (const seg of parsed.caPath) {
      if (!SEGMENT_REGEX.test(seg)) {
        failures.push(`${did} :: invalid segment "${seg}"`);
      }
    }
    // 3. The registry must find at least one entry for the derived path.
    const entries = registry.lookup(parsed.countryCode, parsed.caPath);
    if (entries.length === 0) {
      failures.push(`${did} :: lookup returned no entries (notFound tripwire)`);
    }
  }

  assert.deepEqual(
    failures,
    [],
    `round-trip failures (${failures.length}):\n${failures.slice(0, 40).join('\n')}`,
  );
});

// --- Generation-grouping is preserved --------------------------------------

test('ATT-1070 generation-grouping: Italy CIE root keeps BOTH #key-2016 and #key-2024', () => {
  const store = findTrustStore();
  assert.ok(store, 'no trust store found');
  // The bundled fixture may not include Italy; only assert when present.
  if (!existsSync(resolve(store, 'it', 'current', 'manifest.json'))) {
    return; // skip silently on minimal fixture
  }

  const registry = new TrustRegistry(store);
  registry.load();
  const resolver = new DidPkiResolver(registry);

  const did =
    'did:pki:it:ministero-dellinterno:national-root-ca-for-the-italian-electronic-identity-card';
  const res = resolver.resolve(did);
  assert.ok(res.didDocument, `CIE root did not resolve: ${res.didResolutionMetadata.error}`);

  const keyIds = res.didDocument!.verificationMethod.map(vm => vm.id.split('#')[1]);
  assert.ok(keyIds.includes('key-2016'), `missing key-2016, got: ${keyIds.join(',')}`);
  assert.ok(keyIds.includes('key-2024'), `missing key-2024, got: ${keyIds.join(',')}`);
  // Multi-cert DID keeps EVERY verification method (all generations present).
  assert.ok(
    res.didDocument!.verificationMethod.length >= 2,
    'multi-generation DID dropped a verification method',
  );
});

// --- Charset: no stray/punctuation segments anywhere -----------------------

test('ATT-1070 charset: every derived segment matches SEGMENT_REGEX', () => {
  const store = findTrustStore();
  assert.ok(store, 'no trust store found');

  const registry = new TrustRegistry(store);
  registry.load();

  const bad: string[] = [];
  for (const did of new DidPkiResolver(registry).listDids()) {
    const segments = did.split(':').slice(3); // after did:pki:<cc>
    for (const seg of segments) {
      if (!SEGMENT_REGEX.test(seg)) bad.push(`${did} :: "${seg}"`);
    }
  }
  assert.deepEqual(bad, [], `segments with invalid charset:\n${bad.join('\n')}`);
});
