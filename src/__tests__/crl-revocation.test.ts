/**
 * Tests for the CR Firma Digital CRL revocation service and parser.
 * Run with: npm test  (node --test via tsx)
 *
 * Fixtures (src/__tests__/fixtures/) are generated offline with openssl:
 *   - ca-cert.pem   : self-signed test CA
 *   - wrong-cert.pem: an unrelated CA (for the signature-mismatch case)
 *   - test-crl.der  : a CRL signed by ca-cert.pem, revoking serials 1a2b and ff00,
 *                     with a nextUpdate 7 days after generation.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import { parseCrl, verifyCrlSignature, subjectKeyId } from '../crl-parser.js';
import { CrlRevocationService, type CrCa } from '../crl-revocation.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, 'fixtures');
const crlDer = readFileSync(join(FIXTURES, 'test-crl.der'));
const caCert = readFileSync(join(FIXTURES, 'ca-cert.pem'), 'utf-8');
const wrongCert = readFileSync(join(FIXTURES, 'wrong-cert.pem'), 'utf-8');

// ── Parser ──────────────────────────────────────────────────────────

test('parseCrl extracts issuer, dates and revoked serials', () => {
  const crl = parseCrl(crlDer);
  assert.match(crl.issuer, /CN=TEST CA SINPE/);
  assert.match(crl.issuer, /O=TEST BCCR/);
  assert.ok(crl.thisUpdate.endsWith('Z'));
  assert.ok(crl.nextUpdate && crl.nextUpdate.endsWith('Z'));
  // Serials are lowercase hex, no colons.
  assert.deepEqual(crl.revokedSerials.sort(), ['1a2b', 'ff00']);
  assert.equal(crl.signatureAlgorithmOid, '1.2.840.113549.1.1.11'); // sha256WithRSA
});

test('parseCrl throws on malformed DER', () => {
  assert.throws(() => parseCrl(Buffer.from([0x30, 0x80, 0x01])));
});

// ── Signature verification ──────────────────────────────────────────

test('verifyCrlSignature returns true for the correct CA cert', () => {
  const crl = parseCrl(crlDer);
  assert.equal(verifyCrlSignature(crl, caCert), true);
});

test('verifyCrlSignature returns false for the wrong CA cert', () => {
  const crl = parseCrl(crlDer);
  assert.equal(verifyCrlSignature(crl, wrongCert), false);
});

test('subjectKeyId extracts the SKI hex of a cert', () => {
  const ski = subjectKeyId(caCert);
  assert.ok(ski && /^[0-9a-f]+$/.test(ski));
});

// ── Service (mocked upstream + temp trust store) ────────────────────

function makeTrustStore(): string {
  const root = mkdtempSync(join(tmpdir(), 'crl-trust-'));
  const current = join(root, 'cr', 'current');
  mkdirSync(current, { recursive: true });
  // Place the test CA under BOTH fisica filenames the service looks for.
  writeFileSync(join(current, 'CA SINPE - PERSONA FISICA v2 (2023).pem'), caCert);
  writeFileSync(join(current, 'CA SINPE - PERSONA FISICA v2.pem'), caCert);
  writeFileSync(join(current, 'CA SINPE - PERSONA JURIDICA v2.pem'), caCert);
  return root;
}

const FISICA: CrCa = 'sinpe-persona-fisica';

/**
 * A clock inside the fixture CRL's own validity window.
 *
 * This test used to pass `Date.now()` and assert `stale === false`. The fixture
 * is a static file whose `nextUpdate` is 7 days after it was generated offline
 * (2026-07-29), so the test passed on the day it was written and has failed
 * every day since — a time bomb, and the reason `npm test` was red. It was
 * never wrong about behaviour, only about time.
 *
 * Deriving the clock FROM the fixture makes staleness a property of the data
 * rather than of the calendar. Regenerating the fixture cannot silently
 * re-arm it.
 */
function withinValidity(): number {
  const crl = parseCrl(crlDer);
  return Date.parse(crl.thisUpdate) + 1_000;
}

test('getRevocation merges CRLs, verifies signature, and reports fields', async () => {
  const store = makeTrustStore();
  const svc = new CrlRevocationService(store, async () => crlDer);
  const now = withinValidity();
  const result = await svc.getRevocation(FISICA, now);

  assert.equal(result.ca, FISICA);
  assert.match(result.issuer, /CN=TEST CA SINPE/);
  assert.equal(result.signatureVerified, true);
  assert.deepEqual(result.revokedSerials, ['1a2b', 'ff00']);
  // Both fetched CRLs are identical here → merge dedups to 2 serials.
  assert.equal(result.stale, false); // nextUpdate is in the future for `now`
});

test('signatureVerified is false when CRL is signed by an untrusted CA', async () => {
  // Trust store that only bundles the WRONG cert.
  const root = mkdtempSync(join(tmpdir(), 'crl-trust-bad-'));
  const current = join(root, 'cr', 'current');
  mkdirSync(current, { recursive: true });
  writeFileSync(join(current, 'CA SINPE - PERSONA FISICA v2 (2023).pem'), wrongCert);
  writeFileSync(join(current, 'CA SINPE - PERSONA FISICA v2.pem'), wrongCert);

  const svc = new CrlRevocationService(root, async () => crlDer);
  const result = await svc.getRevocation(FISICA, Date.now());
  assert.equal(result.signatureVerified, false);
  // Data is still returned.
  assert.deepEqual(result.revokedSerials, ['1a2b', 'ff00']);
});

test('stale is true when now is past nextUpdate', async () => {
  const store = makeTrustStore();
  const svc = new CrlRevocationService(store, async () => crlDer);
  const crl = parseCrl(crlDer);
  const past = new Date(crl.nextUpdate!).getTime() + 1000;
  const result = await svc.getRevocation(FISICA, past);
  assert.equal(result.stale, true);
});

test('partial fetch failure still returns data but signatureVerified is false', async () => {
  const store = makeTrustStore();
  let call = 0;
  const svc = new CrlRevocationService(store, async () => {
    call += 1;
    if (call === 1) return crlDer; // first CRL OK
    throw new Error('simulated upstream 500'); // second CRL fails
  });
  const result = await svc.getRevocation(FISICA, Date.now());
  assert.deepEqual(result.revokedSerials, ['1a2b', 'ff00']);
  assert.equal(result.signatureVerified, false); // incomplete view
});

test('getRevocation throws when all CRL fetches fail', async () => {
  const store = makeTrustStore();
  const svc = new CrlRevocationService(store, async () => {
    throw new Error('network down');
  });
  await assert.rejects(() => svc.getRevocation(FISICA, Date.now()), /All CRL fetches failed/);
});

test('cache reuses the parsed result within the freshness window', async () => {
  const store = makeTrustStore();
  let fetches = 0;
  const svc = new CrlRevocationService(store, async () => {
    fetches += 1;
    return crlDer;
  });
  const now = Date.now();
  await svc.getRevocation(FISICA, now);
  await svc.getRevocation(FISICA, now + 1000); // within window
  assert.equal(fetches, 2, 'first call fetches both CRLs, second is cached');
});

test('isSupported guards the CA identifier', () => {
  assert.equal(CrlRevocationService.isSupported('sinpe-persona-fisica'), true);
  assert.equal(CrlRevocationService.isSupported('sinpe-persona-juridica'), true);
  assert.equal(CrlRevocationService.isSupported('bogus'), false);
});
