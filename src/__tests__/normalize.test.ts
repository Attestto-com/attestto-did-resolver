/**
 * Tests for the did:pki derivation / normalization algorithm.
 * Run with: npm test  (node --test via tsx)
 *
 * Focus (ATT-1060): the derived method-specific-id must only contain DID
 * `idchar` characters (ALPHA / DIGIT / "." / "-" / "_"). Subjects containing
 * punctuation such as apostrophes or parentheses previously produced
 * syntactically invalid DIDs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deriveDid, derivePathSegments, normalizeCN, derivePathKey } from '../normalize.js';

/** Full method-specific-id validity: did:pki:<cc>(:<idchar+>)+ */
const DID_PKI_RE = /^did:pki:[a-z]{2}(:[a-z0-9._-]+)+$/;

test('IT Ministero dell\'Interno: apostrophe is stripped, DID is valid', () => {
  const did = deriveDid(
    'it',
    'National root CA for the Italian Electronic Identity Card',
    "Ministero dell'Interno",
  );
  assert.ok(!did.includes("'"), `apostrophe leaked into DID: ${did}`);
  assert.match(did, DID_PKI_RE);
  // dell'interno collapses to dellinterno (no stray characters, word boundary preserved)
  assert.ok(did.includes('ministero-dellinterno'), `unexpected org slug: ${did}`);
});

test('CN with parentheses: parentheses are stripped, DID is valid', () => {
  const did = deriveDid(
    'cr',
    'BANCO CENTRAL DE COSTA RICA (AGENTE ELECTRONICO)',
  );
  assert.ok(!did.includes('('), `open paren leaked into DID: ${did}`);
  assert.ok(!did.includes(')'), `close paren leaked into DID: ${did}`);
  assert.match(did, DID_PKI_RE);
  // (agente-electronico) → agente-electronico
  assert.ok(did.includes('agente-electronico'), `unexpected slug: ${did}`);
});

test('O with parentheses: parentheses are stripped, DID is valid', () => {
  const did = deriveDid(
    'it',
    'Some Root CA',
    'Agenzia (per l\'Italia Digitale)',
  );
  assert.ok(!/[()']/.test(did), `punctuation leaked into DID: ${did}`);
  assert.match(did, DID_PKI_RE);
});

test('CR MICITT country-authority still collapses (O omitted)', () => {
  // O is a CR country authority → CN-only derivation (unchanged behavior).
  const segments = derivePathSegments(
    'cr',
    'CA SINPE - PERSONA FISICA',
    'BANCO CENTRAL DE COSTA RICA',
  );
  assert.deepEqual(segments, ['sinpe', 'persona-fisica']);
});

test('FNMT: accent/kebab + org-dedup behavior unchanged', () => {
  const did = deriveDid('es', 'AC RAIZ FNMT-RCM', 'FNMT-RCM');
  assert.match(did, DID_PKI_RE);
  // org "FNMT-RCM" → "fnmt" ("-rcm" suffix stripped); CN "AC RAIZ FNMT-RCM" → "raiz"
  assert.equal(did, 'did:pki:es:fnmt:raiz');
});

test('accent stripping is preserved (transliteration unchanged)', () => {
  // "Innovación" → "innovacion"
  const segments = normalizeCN('Direccion de Innovación');
  assert.deepEqual(segments, ['direccion-de-innovacion']);
});

// --- Period-stripping tests (ATT-resolve-periods) ---

test('AT A-Trust: abbreviation periods are stripped, no period in DID', () => {
  // "A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr" → no periods
  const did = deriveDid(
    'at',
    'a-sign-premium-mobile-05',
    'A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr',
  );
  assert.ok(!did.includes('.'), `period leaked into DID: ${did}`);
  // parser-compatible: each segment is [a-z0-9][a-z0-9-]*[a-z0-9]
  const segments = did.split(':').slice(3);
  const SEGMENT_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/;
  for (const seg of segments) {
    assert.ok(SEGMENT_RE.test(seg), `segment "${seg}" invalid in: ${did}`);
  }
  // org segment: "a-trust-ges-f-sicherheitssysteme-im-elektr-datenverkehr"
  assert.ok(
    did.includes('a-trust-ges-f-sicherheitssysteme-im-elektr-datenverkehr'),
    `unexpected org slug: ${did}`,
  );
});

test('PT Instituto dos Registos I.P.: "I.P." abbreviation period stripped', () => {
  const did = deriveDid(
    'pt',
    'EC de Autenticação do Cartão de Cidadão',
    'Instituto dos Registos e do Notariado I.P.',
  );
  assert.ok(!did.includes('.'), `period leaked into DID: ${did}`);
  const segments = did.split(':').slice(3);
  const SEGMENT_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/;
  for (const seg of segments) {
    assert.ok(SEGMENT_RE.test(seg), `segment "${seg}" invalid in: ${did}`);
  }
  // org segment: "instituto-dos-registos-e-do-notariado-ip"
  assert.ok(
    did.includes('instituto-dos-registos-e-do-notariado-ip'),
    `unexpected org slug: ${did}`,
  );
});

test('derivePathKey produces same period-free org segment as deriveDid', () => {
  const did = deriveDid(
    'at',
    'a-sign-premium-mobile-05',
    'A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr',
  );
  const pathKey = derivePathKey(
    'a-sign-premium-mobile-05',
    'A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr',
    'at',
  );
  // did:pki:at:<pathKey> should equal did
  assert.equal(`did:pki:at:${pathKey}`, did);
});
