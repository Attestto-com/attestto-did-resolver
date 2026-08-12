/**
 * Regression: DID Document JWK export for key types Node's native
 * `KeyObject.export({ format: 'jwk' })` refuses.
 *
 * Real national PKIs (notably the German HBA/qCA CAs) ship:
 *   - RSA-PSS keys  → native export throws "Unsupported JWK Key Type"
 *   - brainpool EC  → native export throws "Unsupported JWK EC curve"
 * Before the fix these certs surfaced in the registry but failed DID-document
 * build with `internalError`, so their did:pki identifiers never resolved.
 * document.ts now hand-parses the SPKI as a fallback.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey } from 'node:crypto';

import { TrustRegistry } from '../registry.js';
import { DidPkiResolver } from '../pki-resolver.js';

function findTrustStore(): string | null {
  const here = fileURLToPath(new URL('.', import.meta.url));
  const candidates = [
    resolve(here, '../../../attestto-trust/countries'),
    resolve(here, '../../trust-store/countries'),
  ];
  return candidates.find(p => existsSync(p)) ?? null;
}

const B64URL = /^[A-Za-z0-9_-]+$/;

test('JWK fallback: EVERY registry DID resolves (no internalError)', () => {
  const store = findTrustStore();
  assert.ok(store, 'no trust store found');

  const registry = new TrustRegistry(store);
  registry.load();
  const resolver = new DidPkiResolver(registry);

  const failures: string[] = [];
  for (const did of resolver.listDids()) {
    const res = resolver.resolve(did);
    if (!res.didDocument) {
      failures.push(`${did} :: ${res.didResolutionMetadata.error} ${res.didResolutionMetadata.message ?? ''}`);
    }
  }
  assert.deepEqual(
    failures,
    [],
    `${failures.length} DID(s) failed to build a document:\n${failures.slice(0, 30).join('\n')}`,
  );
});

test('JWK fallback: RSA-PSS cert yields a re-importable RSA JWK', () => {
  const store = findTrustStore();
  assert.ok(store, 'no trust store found');
  // German HBA CA ATOS.HBA-qCA1 is an RSA-PSS key.
  if (!existsSync(resolve(store, 'de', 'current', 'atos-hba-qca1.pem'))) return; // skip on minimal fixture

  const registry = new TrustRegistry(store);
  registry.load();
  const resolver = new DidPkiResolver(registry);

  const res = resolver.resolve('did:pki:de:atos-information-technology:hba-qca1');
  assert.ok(res.didDocument, `did not resolve: ${res.didResolutionMetadata.message}`);

  const jwk = res.didDocument!.verificationMethod[0].publicKeyJwk;
  assert.equal(jwk.kty, 'RSA');
  assert.ok(jwk.n && B64URL.test(jwk.n), 'modulus is not base64url');
  assert.ok(jwk.e && B64URL.test(jwk.e), 'exponent is not base64url');
  // The hand-built JWK must re-import as a valid RSA key (proves n/e correct).
  const { 'x5t#S256': _t, ...pure } = jwk;
  const key = createPublicKey({ key: pure as JsonWebKey, format: 'jwk' });
  assert.equal(key.asymmetricKeyType, 'rsa');
  assert.equal(key.asymmetricKeyDetails?.modulusLength, 2048);
});

test('JWK fallback: brainpool EC cert yields EC JWK with curve name + x/y', () => {
  const store = findTrustStore();
  assert.ok(store, 'no trust store found');
  // German HBA CA ATOS.HBA-qCA2 is EC on brainpoolP256r1.
  if (!existsSync(resolve(store, 'de', 'current', 'atos-hba-qca2.pem'))) return; // skip on minimal fixture

  const registry = new TrustRegistry(store);
  registry.load();
  const resolver = new DidPkiResolver(registry);

  const res = resolver.resolve('did:pki:de:atos-information-technology:hba-qca2');
  assert.ok(res.didDocument, `did not resolve: ${res.didResolutionMetadata.message}`);

  const jwk = res.didDocument!.verificationMethod[0].publicKeyJwk;
  assert.equal(jwk.kty, 'EC');
  assert.equal(jwk.crv, 'brainpoolP256r1');
  assert.ok(jwk.x && B64URL.test(jwk.x), 'x is not base64url');
  assert.ok(jwk.y && B64URL.test(jwk.y), 'y is not base64url');
  // P-256-sized curve → 32-byte coordinates.
  assert.equal(Buffer.from(jwk.x!, 'base64url').length, 32);
  assert.equal(Buffer.from(jwk.y!, 'base64url').length, 32);
});
