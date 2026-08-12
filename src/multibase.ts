/**
 * Multibase encoding for verification-method key material (SOC-174).
 *
 * `publicKeyBase58` and `publicKeyMultibase` are not two spellings of one
 * thing. base58 is the bare key bytes; multibase is a base prefix followed by a
 * multicodec-tagged payload, so the same key produces different strings and a
 * decoder told the wrong one either throws or returns unrelated bytes.
 *
 * The resolver previously emitted `publicKeyBase58` under a document declaring
 * the `ed25519-2020` context, which does not define that term — so a JSON-LD
 * processor dropped the key entirely. It also emitted `"z" + hexString` for the
 * ECIES key, where `z` declares base58btc over a payload that was hex. Both
 * failures come from treating an encoding as a formatting detail.
 *
 * This module is deliberately the only place that constructs these strings.
 */
import bs58 from 'bs58'

/**
 * multicodec varint prefixes (`https://github.com/multiformats/multicodec`).
 * `ed25519-pub` is 0xed, varint-encoded as the two bytes `0xed 0x01` — the
 * second byte is part of the varint, not a version.
 */
const ED25519_PUB_PREFIX = Uint8Array.from([0xed, 0x01])

/** Ed25519 raw public keys are 32 bytes. Anything else is not one. */
const ED25519_KEY_BYTES = 32

/**
 * Encode a Solana address (base58 of 32 raw Ed25519 bytes) as the
 * `publicKeyMultibase` value the `Ed25519VerificationKey2020` suite expects.
 *
 * Throws rather than emitting something a consumer cannot decode: a document
 * with a broken key is worse than a resolution failure, because the failure is
 * visible and the broken key is not.
 */
export function solanaAddressToMultibase(address: string): string {
  let raw: Uint8Array
  try {
    raw = bs58.decode(address)
  } catch {
    throw new Error(`owner key is not base58: ${address}`)
  }

  if (raw.length !== ED25519_KEY_BYTES) {
    throw new Error(`owner key is ${raw.length} bytes, expected ${ED25519_KEY_BYTES}`)
  }

  const tagged = new Uint8Array(ED25519_PUB_PREFIX.length + raw.length)
  tagged.set(ED25519_PUB_PREFIX, 0)
  tagged.set(raw, ED25519_PUB_PREFIX.length)

  // `z` is the multibase code for base58btc.
  return `z${bs58.encode(tagged)}`
}
