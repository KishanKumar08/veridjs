import { HMACKey, HMACSigner } from "../crypto/HMACSigner"
import { InputFailureReason, normalizeInput, VIDInput } from "./input"

/**
 * Byte offset where the unsigned payload ends and the signature begins.
 * payload = bytes 0–10 (11 bytes), signature = bytes 11–17 (7 bytes).
 */
const PAYLOAD_END = 11

/**
 * Detailed result from VIDVerifier.verifyDetailed().
 *
 * Prefer verify() for hot paths (returns a plain boolean).
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
  | InputFailureReason
  | "UNKNOWN_KEY_VERSION"   // keyVersion in the ID has no corresponding key in the keys map
  | "SIGNATURE_MISMATCH"    // HMAC verification failed — ID is forged or tampered
  | "DECODE_ERROR"          // no longer produced (strings are fully validated first); kept for type compatibility

/**
 * Stateless verifier for VID identifiers.
 *
 * Keys are expected to be validated by the caller (VID.initialize does this
 * once at startup), so nothing here re-checks them per call.
 */
export class VIDVerifier {
  /**
   * Verifies a VID and returns a plain boolean. Never throws.
   *
   * @param input - VID in any accepted representation.
   * @param keys  - Map of keyVersion → secret (raw bytes or KeyObject).
   * @returns true if the VID is authentic; false for any invalid or forged input.
   */
  static verify(input: VIDInput, keys: ReadonlyMap<number, HMACKey>): boolean {
    return VIDVerifier.verifyDetailed(input, keys).valid
  }

  /**
   * Verifies a VID and returns a typed result with a failure reason. Never throws.
   *
   * ⚠️  NEVER expose the failure reason to external API clients.
   *     Return a generic error to clients; log the reason internally.
   *
   * @param input - VID in any accepted representation.
   * @param keys  - Map of keyVersion → secret (raw bytes or KeyObject).
   * @returns VerifyResult — { valid: true } or { valid: false, reason: ... }
   */
  static verifyDetailed(input: VIDInput, keys: ReadonlyMap<number, HMACKey>): VerifyResult {
    const normalized = normalizeInput(input)
    if (!normalized.ok) {
      return { valid: false, reason: normalized.reason }
    }

    const binary = normalized.binary

    // keyVersion (byte 0) selects the secret, which is what makes rotation work
    const key = keys.get(binary[0])
    if (key === undefined) {
      return { valid: false, reason: "UNKNOWN_KEY_VERSION" }
    }

    const payload = binary.subarray(0, PAYLOAD_END)
    const signature = binary.subarray(PAYLOAD_END)

    if (!HMACSigner.verify(payload, signature, key)) {
      return { valid: false, reason: "SIGNATURE_MISMATCH" }
    }

    return { valid: true }
  }
}
