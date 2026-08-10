/**
 * did:sns identifier parsing — §7, §7.1, §7.2 and §9.2 steps 1-3.
 *
 * Authority: did-sns-spec @ 9e04ffc (v0.4.0). Every branch below cites the
 * sentence it implements. A branch you cannot cite is a branch that is
 * inventing method behaviour — which is how `#key-1` came to exist.
 *
 * ── Why this is a separate module ──────────────────────────────────────────
 *
 * Parsing is pure. The reason the defects here shipped is that the only way to
 * exercise the parser was to call `DidSnsResolver.resolve()`, which opens a
 * Solana RPC connection — so nobody ever did. A pure function needs no network
 * and no fixtures.
 *
 * ── What this module deliberately does NOT decide ──────────────────────────
 *
 * It returns the `name` that §9.2 step 4 hashes, and nothing else. It does not
 * emit a "canonical DID", because what belongs in `didDocument.id` is undefined
 * in the spec (SOC-177 G7) and arguably constrained by DID Core, which expects
 * the resolved document's `id` to be the DID that was resolved. Choosing here
 * would make this module a second source of truth.
 *
 * Also undecided upstream, and therefore not implemented:
 *   - label case normalisation. ABNF ALPHA admits A-Z, but §9.2 step 4 hashes
 *     the bytes, so `Alice` and `alice` derive different PDAs. Passed through
 *     unchanged; SOC-177 must decide.
 *   - whether `.sol` is stripped once or to fixpoint. Implemented as ONCE,
 *     matching the singular wording of step 2.
 */

/** §7.1: `network = "mainnet" / "devnet" / "testnet"`. */
export type SnsNetwork = 'mainnet' | 'devnet' | 'testnet'

export type SnsParseReason =
  /** §9.2 error table: "Malformed syntax, wrong prefix, invalid characters". */
  | 'invalidDid'
  /**
   * §7.2 "two levels maximum". Deliberately NOT `invalidDid`: depth is a
   * resolution policy, not a grammar failure — §7.1's `sns-name` is unbounded,
   * and §9.2 validates depth at step 3, after the DID has parsed. §7.2 says
   * only "rejected by resolver" and names no code, so the caller decides how
   * to render this. SOC-177 asks the spec to name one.
   */
  | 'tooDeep'

export interface ParsedSnsName {
  /** The value §9.2 step 4 hashes: selector removed, `.sol` stripped. */
  name: string
  network: SnsNetwork
}

export type SnsParseResult =
  | { ok: true; value: ParsedSnsName }
  | { ok: false; reason: SnsParseReason; message: string }

/** §7: "A DID using this method MUST begin with `did:sns:`" (lowercase). */
const PREFIX = 'did:sns:'

/** §7.1: reserved as network selectors; MUST NOT resolve as top-level labels. */
const NETWORKS: readonly SnsNetwork[] = ['mainnet', 'devnet', 'testnet']

/** §7.1: `label = 1*( ALPHA / DIGIT / "-" )`. No underscore, no dot, no colon. */
const LABEL = /^[A-Za-z0-9-]+$/

const SOL_SUFFIX = '.sol'
const MAX_LABELS = 2

function bad(reason: SnsParseReason, message: string): SnsParseResult {
  return { ok: false, reason, message }
}

function isNetwork(token: string): token is SnsNetwork {
  return (NETWORKS as readonly string[]).includes(token)
}

export function parseSnsDid(input: string): SnsParseResult {
  if (typeof input !== 'string' || !input.startsWith(PREFIX)) {
    // Case-sensitive on purpose — §7: "the method name MUST be lowercase".
    return bad('invalidDid', `not a did:sns identifier: ${JSON.stringify(input)}`)
  }

  // ── §9.2 step 1: extract sns-name and optional network ───────────────────
  //
  // §7.1's conditional is precise: the first segment is the network component
  // only "when [it] equals one of these tokens AND is followed by another `:`
  // and a non-empty sns-name". Anything else stays part of the name — and a
  // colon is not in `label`, so it will fail the grammar check below rather
  // than being silently swallowed. That is what makes `did:sns:devnet:` and
  // `did:sns:localnet:alice` invalid rather than surprising.
  let rest = input.slice(PREFIX.length)
  let network: SnsNetwork = 'mainnet' // §7.1: "mainnet is implied"

  // §7.1's conditional also requires "a non-empty sns-name" after the colon.
  // That clause is NOT re-checked here: an empty remainder cannot satisfy
  // `label = 1*( … )` below, so the grammar check is its single enforcement.
  // Duplicating it produces a branch no test can distinguish — verified by
  // mutation: replacing the length guard with `true` leaves all 30 tests green.
  const colon = rest.indexOf(':')
  if (colon > 0) {
    const head = rest.slice(0, colon)
    if (isNetwork(head)) {
      network = head
      rest = rest.slice(colon + 1)
    }
  }

  // ── §9.2 step 2: "Strip '.sol' suffix if present" ────────────────────────
  //
  // Anchored to the end and to a dot boundary. An unanchored replace corrupts
  // any name containing the substring — the live defect in CORTEX
  // session-identity.ts:256, where `resol.attestto.sol` becomes `reattestto`.
  // Ordered BEFORE the depth check, per the numbered algorithm: stripping late
  // counts `sol` as a third label and rejects a legal two-level name.
  if (rest.endsWith(SOL_SUFFIX)) rest = rest.slice(0, -SOL_SUFFIX.length)

  // ── §7.1: `sns-name = label *( "." label )` ──────────────────────────────
  const labels = rest.split('.')
  if (labels.length === 0 || labels.some((l) => !LABEL.test(l))) {
    return bad(
      'invalidDid',
      `sns-name must be label *( "." label ) with label = 1*( ALPHA / DIGIT / "-" ): ${JSON.stringify(rest)}`,
    )
  }

  // ── §7.1: reserved tokens are never top-level names ──────────────────────
  //
  // Checked AFTER the strip, so `did:sns:mainnet.sol` cannot smuggle a
  // reserved token past the check by wearing a suffix.
  if (labels.length === 1 && isNetwork(labels[0])) {
    return bad('invalidDid', `${labels[0]} is a reserved network selector, not a name`)
  }

  // ── §9.2 step 3 / §7.2: "two levels maximum (root + one subdomain)" ──────
  if (labels.length > MAX_LABELS) {
    return bad('tooDeep', `SNS supports ${MAX_LABELS} levels maximum, got ${labels.length}: ${rest}`)
  }

  return { ok: true, value: { name: rest, network } }
}
