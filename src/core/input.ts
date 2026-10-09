import { Base32Encoder } from "../encoding/Base32Encoder"
import { VIDValue } from "./VIDValue"

/** Required byte length of a valid VID binary. */
const VID_BYTE_LENGTH = 18

/** Required character length of a base32-encoded VID string. */
const VID_STRING_LENGTH = 29

/**
 * Valid base32 alphabet: A–Z and digits 2–7, either case.
 * Digits 0, 1, 8 and 9 are not part of RFC 4648 base32.
 */
const BASE32_REGEX = /^[A-Za-z2-7]{29}$/

/**
 * Every representation a VID can arrive in.
 * Buffer is covered by Uint8Array (it is a subclass).
 */
export type VIDInput = string | Uint8Array | ArrayBuffer | VIDValue

/**
 * Structural reasons an input cannot be turned into an 18-byte VID binary.
 */
export type InputFailureReason =
  | "NULL_INPUT"            // input is null or undefined
  | "UNSUPPORTED_TYPE"      // input is not string, Uint8Array, Buffer, ArrayBuffer, or VIDValue
  | "INVALID_STRING_LENGTH" // string is not exactly 29 characters (after trimming)
  | "INVALID_STRING_CHARS"  // string contains characters outside the base32 alphabet
  | "NON_CANONICAL_STRING"  // final character has non-zero padding bits (not what generate() emits)
  | "INVALID_BINARY_LENGTH" // binary is not exactly 18 bytes

export type NormalizedInput =
  | { ok: true; binary: Uint8Array }
  | { ok: false; reason: InputFailureReason }

/**
 * Normalizes any accepted VID input to an 18-byte binary without throwing.
 *
 *   string      → trim, validate length / alphabet / canonical form, base32-decode
 *   VIDValue    → toBinary()
 *   Uint8Array  → used as-is (read-only; Buffer included)
 *   ArrayBuffer → wrapped in a Uint8Array view
 */
export function normalizeInput(input: unknown): NormalizedInput {
  if (input === null || input === undefined) {
    return { ok: false, reason: "NULL_INPUT" }
  }

  let binary: Uint8Array

  if (typeof input === "string") {
    const text = input.length === VID_STRING_LENGTH ? input : input.trim()

    if (text.length !== VID_STRING_LENGTH) {
      return { ok: false, reason: "INVALID_STRING_LENGTH" }
    }
    if (!BASE32_REGEX.test(text)) {
      return { ok: false, reason: "INVALID_STRING_CHARS" }
    }

    const upper = text.toUpperCase()
    if (!Base32Encoder.isCanonical(upper)) {
      return { ok: false, reason: "NON_CANONICAL_STRING" }
    }

    binary = Base32Encoder.decode(upper)
  } else if (input instanceof VIDValue) {
    binary = input.toBinary()
  } else if (input instanceof Uint8Array) {
    binary = input
  } else if (input instanceof ArrayBuffer) {
    binary = new Uint8Array(input)
  } else {
    return { ok: false, reason: "UNSUPPORTED_TYPE" }
  }

  if (binary.length !== VID_BYTE_LENGTH) {
    return { ok: false, reason: "INVALID_BINARY_LENGTH" }
  }

  return { ok: true, binary }
}
