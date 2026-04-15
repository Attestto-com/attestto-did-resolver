/**
 * Attestto DID Resolver — Unified Universal Resolver Driver
 *
 * Routes DID resolution requests to method-specific resolvers:
 *   did:pki:* → PKI resolver (national PKI bridge)
 *   did:sns:* → SNS resolver (Solana Name Service)
 *
 * Conforms to DIF Universal Resolver driver spec:
 *   GET /1.0/identifiers/{did} → W3C DID Resolution Result
 *
 * Environment variables:
 *   TRUST_STORE_PATH  — Path to attestto-trust/countries/ (for did:pki)
 *   SOLANA_RPC_URL    — Custom Solana RPC endpoint (for did:sns)
 *   PORT              — HTTP port (defaults to 8080)
 *   LOG_LEVEL         — "debug" | "info" | "warn" | "error" (defaults to "info")
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { TrustRegistry } from './registry.js'
import { DidPkiResolver } from './pki-resolver.js'
import { DidSnsResolver } from './sns-resolver.js'

const PORT = Number(process.env.PORT || 8080)
const LOG_LEVEL = process.env.LOG_LEVEL || 'info'
const TRUST_STORE = process.env.TRUST_STORE_PATH ?? join(dirname(fileURLToPath(import.meta.url)), '..', 'trust-store', 'countries')

// ── Initialize resolvers ────────────────────────────────────────────

const registry = new TrustRegistry(TRUST_STORE)
try {
  registry.load()
} catch (err) {
  console.warn(`[did:pki] Trust store not loaded: ${err instanceof Error ? err.message : err}`)
}
const pkiResolver = new DidPkiResolver(registry)
const snsResolver = new DidSnsResolver()

const pkiDids = pkiResolver.listDids()
log('info', `[did:pki] Loaded ${pkiDids.length} DIDs from trust store`)
log('info', `[did:sns] Solana RPC: ${process.env.SOLANA_RPC_URL || 'mainnet public (default)'}`)

// ── CORS ────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url))
let allowedOrigins: string[] = []
try {
  const raw = readFileSync(join(__dirname, 'cors-whitelist.json'), 'utf-8')
  allowedOrigins = JSON.parse(raw).allowedOrigins || []
} catch {
  allowedOrigins = process.env.NODE_ENV === 'production' ? [] : ['*']
}

function setCorsHeaders(req: IncomingMessage, res: ServerResponse): boolean {
  const origin = req.headers.origin || ''
  if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*')
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept')
    res.setHeader('Access-Control-Max-Age', '86400')
    return true
  }
  return false
}

// ── Logging ─────────────────────────────────────────────────────────

function log(level: string, message: string, data?: Record<string, unknown>) {
  const levels = ['debug', 'info', 'warn', 'error']
  if (levels.indexOf(level) < levels.indexOf(LOG_LEVEL)) return
  const entry = { timestamp: new Date().toISOString(), level, message, ...data }
  console.log(JSON.stringify(entry))
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  const json = JSON.stringify(body, null, 2)
  res.writeHead(status, {
    'Content-Type': 'application/did+ld+json',
    'Content-Length': Buffer.byteLength(json),
  })
  res.end(json)
}

// ── Request handler ─────────────────────────────────────────────────

async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`)
  const method = req.method || 'GET'

  // CORS
  const corsAllowed = setCorsHeaders(req, res)
  if (method === 'OPTIONS') {
    res.writeHead(corsAllowed ? 204 : 403)
    res.end()
    return
  }
  if (!corsAllowed && req.headers.origin) {
    sendJson(res, 403, { error: 'Origin not allowed', origin: req.headers.origin })
    return
  }

  // Health check
  if (url.pathname === '/health' || url.pathname === '/') {
    sendJson(res, 200, {
      status: 'ok',
      driver: 'attestto-did-resolver',
      version: '0.1.0',
      supportedMethods: ['pki', 'sns'],
      pkiDids: pkiDids.length,
    })
    return
  }

  // Properties endpoint (DIF driver convention)
  if (url.pathname === '/1.0/properties') {
    sendJson(res, 200, {
      'driver-did-pki': {
        http: {
          pattern: '^did:pki:.+$',
          resolverUri: `http://localhost:${PORT}/1.0/identifiers/`,
          testIdentifiers: [
            'did:pki:cr:raiz-nacional',
            'did:pki:cr:sinpe:persona-fisica',
          ],
        },
        method: 'pki',
        implementation: 'Attestto did:pki Resolver',
        implementationUrl: 'https://github.com/Attestto-com/did-pki-resolver',
      },
      'driver-did-sns': {
        http: {
          pattern: '^did:sns:.+$',
          resolverUri: `http://localhost:${PORT}/1.0/identifiers/`,
          testIdentifiers: [
            'did:sns:bonfida',
            'did:sns:attestto',
            'did:sns:devnet:test.attestto',
          ],
        },
        method: 'sns',
        implementation: 'Attestto did:sns Resolver',
        implementationUrl: 'https://github.com/Attestto-com/attestto-did-resolver',
      },
    })
    return
  }

  // DID Resolution endpoint — route by method
  const identifierMatch = url.pathname.match(/^\/1\.0\/identifiers\/(.+)$/)
  if (identifierMatch && method === 'GET') {
    const did = decodeURIComponent(identifierMatch[1])

    log('info', 'Resolving DID', { did })
    const startTime = Date.now()

    let result: any

    if (did.startsWith('did:pki:')) {
      result = pkiResolver.resolve(did)
    } else if (did.startsWith('did:sns:')) {
      result = await snsResolver.resolve(did)
    } else {
      sendJson(res, 400, {
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: null,
        didResolutionMetadata: {
          error: 'methodNotSupported',
          errorMessage: `This resolver supports did:pki and did:sns, got: ${did}`,
        },
        didDocumentMetadata: {},
      })
      return
    }

    const duration = Date.now() - startTime
    const hasError = result.didResolutionMetadata?.error
    const status = hasError
      ? (hasError === 'notFound' ? 404 : hasError === 'invalidDid' ? 400 : 500)
      : 200

    log(
      hasError ? 'warn' : 'info',
      hasError ? 'Resolution failed' : 'Resolution successful',
      { did, duration, error: hasError }
    )

    sendJson(res, status, result)
    return
  }

  // List resolvable did:pki DIDs
  if (url.pathname === '/1.0/identifiers' && method === 'GET') {
    sendJson(res, 200, { pkiDids: pkiResolver.listDids() })
    return
  }

  sendJson(res, 404, { error: 'Not found', path: url.pathname })
}

// ── Server ──────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  try {
    await handleRequest(req, res)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error'
    log('error', 'Unhandled error', { error: message })
    sendJson(res, 500, {
      '@context': 'https://w3id.org/did-resolution/v1',
      didDocument: null,
      didResolutionMetadata: { error: 'internalError', errorMessage: message },
      didDocumentMetadata: {},
    })
  }
})

server.listen(PORT, () => {
  log('info', `Attestto DID Resolver listening on port ${PORT}`, {
    methods: ['did:pki', 'did:sns'],
    pkiDids: pkiDids.length,
  })
})
