import crypto from "crypto"

/**
 * Number of bytes taken from the HMAC-SHA256 output (32 bytes) to form
 * the VID signature field.
 *
 * Security analysis of 7-byte (56-bit) truncation:
 *   - 2^56 ≈ 72 quadrillion possible signature values
 *   - Random forgery probability per attempt: 1 / 72,057,594,037,927,936
 *   - At 1,000,000 attempts/second: expected time to forge ≈ 2,283 years
 *   - In practice, API rate limiting (100 req/s) makes this computationally
 *     infeasible regardless of signature length
 *
 * Why not use all 32 bytes?
 *   VID binary is fixed at 18 bytes. The payload is 11 bytes, leaving
 *   exactly 7 bytes for the signature field. Using fewer bytes would reduce
 *   the signature-to-payload ratio; using more would require a larger binary.
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
 * Minimum byte length for a signable payload.
 */
const MIN_PAYLOAD_BYTES = 1

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
   * Signs a payload with HMAC-SHA256 and returns the first SIGNATURE_BYTES
   * bytes of the digest as the truncated signature.
   *
   * The returned Uint8Array is a fresh allocation — the caller owns it and
   * can safely store or compare it without risk of mutation from this class.
   *
   * @param payload - Data to sign. For VIDs this is always the 11-byte header
   *                  [keyVersion | timestamp | nodeId | sequence].
   * @param secret  - Derived HMAC key. Must be at least MIN_SECRET_BYTES (32) bytes.
   *
   * @returns Uint8Array of length SIGNATURE_BYTES (7) containing the truncated HMAC.
   *
   * @throws {TypeError}  payload or secret is not a Uint8Array.
   * @throws {RangeError} payload is empty or secret is shorter than MIN_SECRET_BYTES.
   */
  static sign(payload: Uint8Array, secret: Uint8Array): Uint8Array {
    HMACSigner.validatePayload(payload)
    HMACSigner.validateSecret(secret)

    const hmac = crypto.createHmac(HMAC_ALGORITHM, secret)

    // Update the hmac with data
    hmac.update(Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength))

    const fullDigest = hmac.digest() // Buffer, 32 bytes

    // Truncate to SIGNATURE_BYTES
    return new Uint8Array(fullDigest.buffer, fullDigest.byteOffset, SIGNATURE_BYTES)
  }

  /**
   * Verifies a VID signature in constant time.
   *
   * Recomputes the expected HMAC over the payload and compares it to the
   * provided signature byte-for-byte using crypto.timingSafeEqual().
   *
   * @param payload   - The 11-byte unsigned VID payload.
   * @param signature - The 7-byte signature extracted from the VID binary.
   * @param secret    - The HMAC key for the keyVersion embedded in this VID.
   *
   * @returns true if the signature is authentic; false for any invalid input
   *          or signature mismatch.
   */
  static verify(
    payload: Uint8Array,
    signature: Uint8Array,
    secret: Uint8Array
  ): boolean {

    // All guards return false — never throw. Verification is called on
    if (
      !(payload instanceof Uint8Array) ||
      !(signature instanceof Uint8Array) ||
      !(secret instanceof Uint8Array)
    ) {
      return false
    }

    if (payload.length < MIN_PAYLOAD_BYTES) {
      return false
    }

    if (secret.length < MIN_SECRET_BYTES) {
      return false
    }

    // Reject before recomputing — cheap length check avoids HMAC computation
    if (signature.length !== SIGNATURE_BYTES) {
      return false
    }

    // Recompute expected signature. sign() validates payload + secret again
    let expected: Uint8Array
    try {
      expected = HMACSigner.sign(payload, secret)
    } catch {
      return false
    }

    const expectedBuffer = Buffer.from(
      expected.buffer,
      expected.byteOffset,
      expected.byteLength
    )

    const signatureBuffer = Buffer.from(
      signature.buffer,
      signature.byteOffset,
      signature.byteLength
    )

    if (expectedBuffer.length !== signatureBuffer.length) {
      return false
    }

    return crypto.timingSafeEqual(expectedBuffer, signatureBuffer)
  }


  /**
   * Validates the payload for sign().
   * Throws on programmer error — sign() is called with controlled internal data.
   */
  private static validatePayload(payload: Uint8Array): void {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError(
        `HMACSigner: payload must be a Uint8Array. Received: ${typeof payload}`
      )
    }

    if (payload.length < MIN_PAYLOAD_BYTES) {
      throw new RangeError(
        `HMACSigner: payload must not be empty. ` +
        `VID payloads are always ${11} bytes. Received ${payload.length} bytes.`
      )
    }
  }

  /**
   * Validates the secret key for sign().
   * Throws on programmer error — a short secret is a configuration mistake,
   * not a runtime condition.
   */
  private static validateSecret(secret: Uint8Array): void {
    if (!(secret instanceof Uint8Array)) {
      throw new TypeError(
        `HMACSigner: secret must be a Uint8Array. Received: ${typeof secret}`
      )
    }

    if (secret.length < MIN_SECRET_BYTES) {
      throw new RangeError(
        `HMACSigner: secret must be at least ${MIN_SECRET_BYTES} bytes. ` +
        `Received ${secret.length} bytes. ` +
        `Use VID.deriveKey() to produce a valid 32-byte key from your secret string.`
      )
    }
  }
}