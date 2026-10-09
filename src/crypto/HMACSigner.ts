import crypto, { KeyObject } from "crypto"

/**
 * Number of bytes taken from the HMAC-SHA256 output (32 bytes) to form
 * the VID signature field.
 *
 * Security analysis of 7-byte (56-bit) truncation:
 *   - 2^56 ≈ 72 quadrillion possible signature values
 *   - Random forgery probability per attempt: 1 / 72,057,594,037,927,936
 *   - At 1,000,000 attempts/second: expected time to forge ≈ 1,142 years
 *   - In practice, API rate limiting (100 req/s) makes this computationally
 *     infeasible regardless of signature length
 *
 * Why not use all 32 bytes?
 *   VID binary is fixed at 18 bytes. The payload is 11 bytes, leaving
 *   exactly 7 bytes for the signature field.
 */
const SIGNATURE_BYTES = 7

/**
 * HMAC algorithm. SHA-256 output is 32 bytes
 */
const HMAC_ALGORITHM = "sha256"

/**
 * Minimum byte length for a valid HMAC secret key.
 */
const MIN_SECRET_BYTES = 32

/**
 * A secret the signer accepts: raw bytes, or a KeyObject prepared once
 * with HMACSigner.createKey(). KeyObjects skip per-call validation and
 * key import, so they are what the VID engine uses on its hot paths.
 */
export type HMACKey = Uint8Array | KeyObject

// ─────────────────────────────────────────────────────────────────────────────
// HMACSigner
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Stateless HMAC-SHA256 signing and verification for VID payloads.
 *
 * Responsibilities:
 *   - Signs an 11-byte VID payload → produces a 7-byte truncated signature
 *   - Verifies a signature against a payload using constant-time comparison
 *
 * Security properties:
 *   - Constant-time comparison via crypto.timingSafeEqual() — no timing leaks
 *   - HMAC-SHA256 is collision-resistant and pre-image resistant
 *   - Truncation to 7 bytes is documented and acceptable given rate limiting
 */
export class HMACSigner {

  /**
   * Exposed as a constant so callers can reference the expected signature length without hardcoding 7.
   */
  static readonly SIGNATURE_BYTES = SIGNATURE_BYTES

  /**
   * Validates a raw secret once and wraps it in a KeyObject for reuse.
   *
   * @throws {TypeError}  secret is not a Uint8Array.
   * @throws {RangeError} secret is shorter than 32 bytes.
   */
  static createKey(secret: Uint8Array): KeyObject {
    HMACSigner.validateSecret(secret)
    return crypto.createSecretKey(secret)
  }

  /**
   * Signs a payload with HMAC-SHA256 and returns the first SIGNATURE_BYTES
   * bytes of the digest.
   *
   * @param payload - Bytes to sign (the 11-byte VID payload).
   * @param key     - Raw secret (≥ 32 bytes) or a KeyObject from createKey().
   * @returns A fresh SIGNATURE_BYTES-long Uint8Array.
   *
   * @throws {TypeError}  payload is not a Uint8Array, or key has the wrong type.
   * @throws {RangeError} payload is empty, or a raw key is shorter than 32 bytes.
   */
  static sign(payload: Uint8Array, key: HMACKey): Uint8Array {
    const out = new Uint8Array(SIGNATURE_BYTES)
    HMACSigner.signInto(payload, key, out, 0)
    return out
  }

  /**
   * Signs a payload and writes the truncated signature straight into `out`
   * at `offset`, avoiding an intermediate allocation.
   *
   * @throws Same as sign().
   */
  static signInto(payload: Uint8Array, key: HMACKey, out: Uint8Array, offset: number): void {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError(
        `HMACSigner: payload must be a Uint8Array. Received: ${typeof payload}`
      )
    }

    if (payload.length === 0) {
      throw new RangeError(`HMACSigner: payload must not be empty.`)
    }

    const digest = crypto
      .createHmac(HMAC_ALGORITHM, HMACSigner.toKeyObject(key))
      .update(payload)
      .digest()

    out.set(digest.subarray(0, SIGNATURE_BYTES), offset)
  }

  /**
   * Verifies a truncated signature against a payload in constant time.
   *
   * Never throws: any malformed argument yields false.
   *
   * @param payload   - Bytes that were signed.
   * @param signature - SIGNATURE_BYTES-long signature to check.
   * @param key       - Raw secret (≥ 32 bytes) or a KeyObject from createKey().
   * @returns true if the signature matches.
   */
  static verify(payload: Uint8Array, signature: Uint8Array, key: HMACKey): boolean {
    if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
      return false
    }

    let expected: Uint8Array
    try {
      expected = HMACSigner.sign(payload, key)
    } catch {
      return false
    }

    return crypto.timingSafeEqual(expected, signature)
  }

  private static toKeyObject(key: HMACKey): KeyObject {
    if (key instanceof KeyObject) {
      return key
    }
    return HMACSigner.createKey(key)
  }

  private static validateSecret(secret: Uint8Array): void {
    if (!(secret instanceof Uint8Array)) {
      throw new TypeError(
        `HMACSigner: secret must be a Uint8Array or KeyObject. Received: ${typeof secret}`
      )
    }
    if (secret.length < MIN_SECRET_BYTES) {
      throw new RangeError(
        `HMACSigner: secret must be at least ${MIN_SECRET_BYTES} bytes. ` +
        `Received ${secret.length} bytes.`
      )
    }
  }
}
