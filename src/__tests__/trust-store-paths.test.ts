/**
 * SOC-176 — `manifest.certificates[].file` is a path, and nothing checked it.
 *
 * `registry.ts` builds every PEM path as
 * `join(trustStorePath, cc, 'current', cert.file)`. `join` RESOLVES `..`
 * rather than rejecting it, so a manifest entry of `../../../outside/x.pem`
 * escapes the trust store and the process reads whatever its user can read.
 *
 * The trust store is not request input — it arrives as an `@attestto/trust`
 * tarball from npm or GitHub. That is what makes it worth constraining rather
 * than what excuses it: a manifest is DATA the resolver performs filesystem
 * operations from, re-fetched over the network on a timer (`trust-refresh.ts`),
 * and this check is the only thing between a bad publish and an arbitrary read.
 * Certificates live one directory deep, always; a separator has no business
 * appearing in the field at all.
 *
 * The rule enforced below is deliberately narrower than "no `..`": `cert.file`
 * must be a **plain filename**. Blocklisting traversal invites the usual
 * bypasses (`....//`, encodings, absolute paths); allowing exactly one shape
 * has no bypasses to enumerate.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { TrustRegistry } from '../registry.js'

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')
const CERT_PEM = readFileSync(join(FIXTURES, 'ca-cert.pem'), 'utf-8')

/**
 * A trust store whose `cr` manifest names `file` for its single certificate.
 * The secret sits OUTSIDE the store, where a well-behaved manifest can never
 * reach and a traversing one can.
 *
 * `extraFiles` lets a test place the named file inside the country directory,
 * so "rejected by the name check" can be told apart from "absent".
 */
function storeWith(file: string, extraFiles: string[] = []) {
  const root = mkdtempSync(join(tmpdir(), 'trust-paths-'))
  const outside = join(root, 'outside')
  mkdirSync(outside, { recursive: true })
  // PEM-shaped on purpose: if traversal works, the escaped file parses as a
  // certificate and its key material reaches the DID document. A file that
  // merely crashed the parser would understate what the bug allows.
  writeFileSync(join(outside, 'secret.pem'), CERT_PEM)

  const countries = join(root, 'countries')
  const current = join(countries, 'cr', 'current')
  mkdirSync(join(current, 'sub'), { recursive: true })
  writeFileSync(join(current, 'sub', 'legit.pem'), CERT_PEM)
  for (const name of extraFiles) writeFileSync(join(current, name), CERT_PEM)

  writeFileSync(
    join(current, 'manifest.json'),
    JSON.stringify({
      country: 'CR',
      certificates: [
        {
          file,
          subject: 'CN=Traversal Probe',
          issuer: 'CN=Traversal Probe',
          role: 'root',
          validFrom: '2020-01-01T00:00:00Z',
          validTo: '2040-01-01T00:00:00Z',
        },
      ],
    }),
  )
  return { countriesDir: countries }
}

function didsFor(file: string, extraFiles: string[] = []) {
  const { countriesDir } = storeWith(file, extraFiles)
  const registry = new TrustRegistry(countriesDir)
  registry.load()
  return registry.getAllDids()
}

describe('a manifest cannot name a file outside its own country directory', () => {
  const ESCAPES = [
    '../../outside/secret.pem',
    '../current/../../../outside/secret.pem',
    './../../outside/secret.pem',
    'sub/../../../outside/secret.pem',
    '/etc/passwd',
    '..\\..\\outside\\secret.pem',
  ]

  for (const file of ESCAPES) {
    test(`rejects ${JSON.stringify(file)}`, () => {
      // Nothing is indexed from a rejected entry: no DID, so no document, so
      // no path by which the escaped bytes reach a response.
      assert.deepEqual(didsFor(file), [], `${file} must not produce a DID`)
    })
  }

  test('a separator is rejected even when it stays inside the store', () => {
    // `sub/legit.pem` exists and is harmless in itself — the test creates it.
    // So this fails by the NAME check, not by absence, which is what makes the
    // rule "a plain filename" rather than "no `..`". The former has no
    // bypasses; the latter has a decade of them.
    assert.deepEqual(didsFor('sub/legit.pem'), [])
  })
})

describe('the ordinary case still works', () => {
  test('a plain filename is loaded and produces a DID', () => {
    // The control. A guard that rejected everything would satisfy every
    // assertion above while breaking the resolver completely.
    assert.equal(didsFor('legit.pem', ['legit.pem']).length, 1)
  })

  test('spaces and parentheses are still accepted', () => {
    // Real trust-store filenames look like
    // `CA SINPE - PERSONA FISICA v2 (2023).pem`. A guard that got overzealous
    // about punctuation would silently empty the Costa Rican registry — which
    // is the failure mode a name check is most likely to have.
    const name = 'CA SINPE - PERSONA FISICA v2 (2023).pem'
    assert.equal(didsFor(name, [name]).length, 1)
  })
})
