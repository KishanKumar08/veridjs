import { HMACSigner } from "../crypto/HMACSigner"
import { Base32Encoder } from "../encoding/Base32Encoder"
import { VIDValue } from "./VIDValue"

/**
 * Required byte length of a valid VID binary.
 */
const VID_BYTE_LENGTH = 18

/** Required character length of a base32-encoded VID string. */
const VID_STRING_LENGTH = 29

/**
 * Byte offset where the unsigned payload ends and the signature begins.
 * payload = bytes 0–10 (11 bytes), signature = bytes 11–17 (7 bytes).
 */
const PAYLOAD_END = 11

/** Number of bytes in the HMAC signature field. */
const SIGNATURE_BYTES = 7

/**
 * Valid base32 alphabet: uppercase A–Z and digits 2–7.
 * Digits 0 and 1 are excluded (visually ambiguous with O and I).
 */
const BASE32_REGEX = /^[A-Z2-7]{29}$/


/**
 * Detailed result from VIDVerifier.verifyDetailed().
 *
 * Prefer verify() for hot paths (returns a plain boolean, zero allocation).
 * Use verifyDetailed() in middleware, audit logging, or debugging where
 * understanding the failure reason matters.
 */
export type VerifyResult =
  | { valid: true }
  | { valid: false; reason: VerifyFailureReason }

/**
 * All possible reasons a VID verification can fail.
 * Useful for metrics, structured logging, and debugging.
 */
export type VerifyFailureReason =
  | "NULL_INPUT"            // input is null or undefined
  | "UNSUPPORTED_TYPE"      // input type is not string, Uint8Array, Buffer, ArrayBuffer, or VIDValue
  | "INVALID_STRING_LENGTH" // string is not exactly 26 characters
  | "INVALID_STRING_CHARS"  // string contains characters outside base32 alphabet
  | "INVALID_BINARY_LENGTH" // binary is not exactly 18 bytes
  | "UNKNOWN_KEY_VERSION"   // keyVersion in the ID has no corresponding key in the keys map
  | "SIGNATURE_MISMATCH"    // HMAC verification failed — ID is forged or tampered
  | "DECODE_ERROR"          // base32 decoding threw an unexpected error


/**
 * Stateless verifier for VID identifiers.
*/
export class VIDVerifier {
  /**
   * Verifies a VID and returns a plain boolean.
   *
   * Use this on hot paths (request validation, middleware) where you only
   * need to know valid/invalid and the failure reason is not needed.
   *
   * Accepts all VID representations:
   *   - string     → base32-encoded, 26 characters
   *   - Uint8Array → raw 18-byte binary
   *   - Buffer     → Node.js Buffer (subclass of Uint8Array)
   *   - ArrayBuffer → raw ArrayBuffer (WebAPI environments)
   *   - VIDValue   → first-class VID object
   *
   * @param input - VID in any accepted representation.
   * @param keys  - Map of keyVersion → secret Uint8Array. Must contain at least one entry.
   * @returns true if the VID is authentic; false for any invalid or forged input.
   *
   * @throws {TypeError}  If keys is not a Map.
   * @throws {RangeError} If keys Map is empty.
   *
   * @example
   * ```ts
   * const keys = new Map([[1, secretBytes]])
   *
   * vid.verify("AEAZY4DVF7PQAKQAAA2PMOJS2DIBB")  // string
   * vid.verify(id.toBinary())                     // Uint8Array
   * vid.verify(id)                                // VIDValue
   * ```
   */
  static verify(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue,
    keys: Map<number, Uint8Array>
  ): boolean {
    VIDVerifier.validateKeys(keys)
    return VIDVerifier.verifyDetailed(input, keys).valid
  }

  /**
   * Verifies a VID and returns a typed result with a failure reason.
   *
   * Use this in middleware, audit logging, or debugging where you need
   * to understand and record why a VID failed.
   *
   * ⚠️  NEVER expose the failure reason to external API clients.
   *     Return a generic error to clients; log the reason internally.
   *     Detailed failure reasons help attackers craft better forgeries.
   *
   * @param input - VID in any accepted representation.
   * @param keys  - Map of keyVersion → secret Uint8Array.
   * @returns VerifyResult — { valid: true } or { valid: false, reason: ... }
   *
   * @throws {TypeError}  If keys is not a Map.
   * @throws {RangeError} If keys Map is empty.
   *
   * @example
   * ```ts
   * const result = VIDVerifier.verifyDetailed(input, keys)
   * if (!result.valid) {
   *   logger.warn("VID verification failed", { reason: result.reason })
   *   return res.status(400).json({ error: "Invalid ID" }) // generic to client
   * }
   * ```
   */
  static verifyDetailed(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue,
    keys: Map<number, Uint8Array>
  ): VerifyResult {
    VIDVerifier.validateKeys(keys)

    // Step 1: Normalize input to binary
    const normalized = VIDVerifier.normalizeToBinary(input)
    if (!normalized.ok) {
      return { valid: false, reason: normalized.reason }
    }

    const binary = normalized.binary
    
    // Step 2: Validate binary length
    if (binary.length !== VID_BYTE_LENGTH) {
      return { valid: false, reason: "INVALID_BINARY_LENGTH" }
    }

    // Step 3: Extract keyVersion (byte 0) and look up the corresponding secret
    const keyVersion = binary[0]
    const secret = keys.get(keyVersion)
    
    if (!secret || secret.length === 0) {
      return { valid: false, reason: "UNKNOWN_KEY_VERSION" }
    }

    // Step 4: Split payload (bytes 0–10) from signature (bytes 11–17)
    const payload = binary.subarray(0, PAYLOAD_END)
    const embeddedSignature = binary.subarray(PAYLOAD_END, PAYLOAD_END + SIGNATURE_BYTES)

    // Step 5: HMAC-SHA256 over payload, constant-time compare to embedded signature
    const isValid = HMACSigner.verify(payload, embeddedSignature, secret)

    if (!isValid) {
      return { valid: false, reason: "SIGNATURE_MISMATCH" }
    }

    return { valid: true }
  }

  /**
   * Normalizes any accepted VID input type to a raw Uint8Array binary.
   *
   * Returns a discriminated union result rather than throwing, so the
   * caller (verifyDetailed) can map failures to typed VerifyFailureReasons
   * and verify() can silently return false for all invalid inputs.
   *
   * Input types handled:
   *   string     → validate format, then base32-decode to 18 bytes
   *   VIDValue   → call toBinary() (always returns a defensive copy)
   *   Uint8Array → use directly (no copy needed — verifier is read-only)
   *   Buffer     → wrap in Uint8Array view (Buffer extends Uint8Array)
   *   ArrayBuffer → wrap in Uint8Array view
   *   null/undefined → NULL_INPUT failure
   *   anything else  → UNSUPPORTED_TYPE failure
   */
  private static normalizeToBinary(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue
  ):
    | { ok: true; binary: Uint8Array }
    | { ok: false; reason: VerifyFailureReason } {
    // ── null / undefined ────────────────────────────────────────────────────
    if (input === null || input === undefined) {
      return { ok: false, reason: "NULL_INPUT" }
    }

    // ── VIDValue ────────────────────────────────────────────────────────────
    if (input instanceof VIDValue) {
      return { ok: true, binary: input.toBinary() }
    }

    // ── string ──────────────────────────────────────────────────────────────
    if (typeof input === "string") {
      const trimmed = input.trim().toUpperCase()

      // Validate length before attempting decode — cheap, catches most bad input
      if (trimmed.length !== VID_STRING_LENGTH) {
        return { ok: false, reason: "INVALID_STRING_LENGTH" }
      }

      // Validate character set — base32 uses A–Z and 2–7 only
      if (!BASE32_REGEX.test(trimmed)) {
        return { ok: false, reason: "INVALID_STRING_CHARS" }
      }

      // Decode
      try {
        const binary = Base32Encoder.decode(trimmed)
        return { ok: true, binary }
      } catch {
        return { ok: false, reason: "DECODE_ERROR" }
      }
    }

    // ── Buffer (Node.js) ─────────────────────────────────────────────────────
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(input)) {
      return { ok: true, binary: new Uint8Array(input.buffer, input.byteOffset, input.byteLength) }
    }

    // ── Uint8Array ───────────────────────────────────────────────────────────
    if (input instanceof Uint8Array) {
      return { ok: true, binary: input }
    }

    // ── ArrayBuffer ──────────────────────────────────────────────────────────
    if (input instanceof ArrayBuffer) {
      return { ok: true, binary: new Uint8Array(input) }
    }

    // ── Unsupported ──────────────────────────────────────────────────────────
    return { ok: false, reason: "UNSUPPORTED_TYPE" }
  }

  /**
   * Validates the keys Map before any verification attempt.
   *
   * @throws {TypeError}  If keys is not a Map instance.
   * @throws {RangeError} If keys Map is empty (no keys = can never verify anything).
   * @throws {TypeError}  If any key value is not a Uint8Array or is empty.
   */
  private static validateKeys(keys: Map<number, Uint8Array>): void {
    if (!(keys instanceof Map)) {
      throw new TypeError(
        `VIDVerifier: keys must be a Map<number, Uint8Array>. ` +
        `Received: ${typeof keys}. ` +
        `Build it as: new Map([[1, secretBytes], [2, newSecretBytes]])`
      )
    }

    if (keys.size === 0) {
      throw new RangeError(
        `VIDVerifier: keys Map is empty. ` +
        `Provide at least one entry: new Map([[1, secretBytes]])`
      )
    }

    for (const [version, secret] of keys) {
      if (!Number.isInteger(version) || version < 0 || version > 255) {
        throw new RangeError(
          `VIDVerifier: key version must be an integer between 0 and 255. ` +
          `Received: ${version}`
        )
      }

      if (!(secret instanceof Uint8Array) || secret.length === 0) {
        throw new TypeError(
          `VIDVerifier: secret for keyVersion ${version} must be a non-empty Uint8Array.`
        )
      }

      if (secret.length < 32) {
        throw new RangeError(
          `VIDVerifier: secret for keyVersion ${version} must be at least 32 bytes (256 bits). ` +
          `Received ${secret.length} bytes.`
        )
      }
    }
  }
}