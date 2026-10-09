import { Base32Encoder } from "../encoding/Base32Encoder"
import { VIDMetadata } from "../types"
import { decodeMetadata } from "./metadata"

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Required byte length of every VID binary.
 */
const VID_BYTE_LENGTH = 18

/** Required character length of a base32-encoded VID string. */
const VID_STRING_LENGTH = 29

/**
 * Regex that validates a base32-encoded VID string.
 * Accepts uppercase A–Z and digits 2–7 (standard base32 alphabet), exactly 29 chars.
 */
const VID_STRING_REGEX = /^[A-Z2-7]{29}$/


/**
 * Immutable value object wrapping an 18-byte VID binary.
 *
 * Responsibilities:
 *   - Holds the binary representation as a defensive copy
 *   - Provides string output (base32, 29 chars) via toString() / toJSON()
 *   - Provides binary output (Uint8Array, 18 bytes) via toBinary()
 *   - Exposes structured metadata via parse()
 *   - Supports value equality via equals() and ordering via VIDValue.compare()
 *
 * Security model:
 *   VIDValue is a data container — it does NOT verify the HMAC signature.
 *   Cryptographic verification is the responsibility of the VID facade
 *   (vid.verify()). This separation keeps VIDValue dependency-free and
 *   ensures verification is explicit, never implicit.
 *
 * Immutability:
 *   - The internal binary is a defensive copy of the constructor input
 *   - toBinary() returns another defensive copy — callers cannot mutate internal state
 */
export class VIDValue {

  /** Internal 18-byte binary. Never exposed directly — always copied on output. */
  private readonly binary: Uint8Array

  /** Lazily cached base32 string. Computed on first toString() call. */
  private cachedString?: string

  // ─── Constructor ────────────────────────────────────────────────────────

  /**
   * Constructs a VIDValue from a raw 18-byte binary.
   *
   * Accepts Uint8Array or Buffer (Buffer extends Uint8Array).
   * Makes a defensive copy — mutations to the original input have no effect.
   *
   * @param binary - Raw 18-byte VID binary.
   *
   * @throws {TypeError}  If binary is null, undefined, or not a Uint8Array / Buffer.
   * @throws {RangeError} If binary is not exactly 18 bytes.
   */
  constructor(binary: Uint8Array) {
    if (binary == null) {
      throw new TypeError(
        `VIDValue: constructor requires a Uint8Array, received ${binary === null ? "null" : "undefined"}.`
      )
    }

    if (!(binary instanceof Uint8Array)) {
      throw new TypeError(
        `VIDValue: constructor requires a Uint8Array (or Buffer). ` +
        `Received: ${typeof binary}`
      )
    }

    if (binary.length !== VID_BYTE_LENGTH) {
      throw new RangeError(
        `VIDValue: binary must be exactly ${VID_BYTE_LENGTH} bytes. ` +
        `Received ${binary.length} bytes. ` +
        `Ensure this binary was produced by vid.generate().`
      )
    }

    this.binary = new Uint8Array(binary)
  }

  /**
   * Returns the base32-encoded string representation of this VID.
   *
   * Format: 29 uppercase characters from the RFC 4648 base32 alphabet (A–Z, 2–7).
   * Example: "AEAZY4DVF7PQAKQAADFM7JS2DIBBQ"
   *
   * Computed once on first call, then cached.
   *
   * @returns 29-character base32 string.
   */
  toString(): string {
    if (this.cachedString === undefined) {
      this.cachedString = Base32Encoder.encode(this.binary)
    }
    return this.cachedString
  }

  /**
   * JSON form is the base32 string, so `JSON.stringify({ id })` and
   * `res.json({ id })` produce `{"id":"AEAZY..."}` instead of a byte map.
   */
  toJSON(): string {
    return this.toString()
  }

  /**
   * Returns the raw 18-byte binary representation of this VID.
   *
   * Use cases: database storage (MongoDB _id, PostgreSQL BYTEA),
   * Redis keys, binary wire protocols, high-performance pipelines.
   *
   * @returns A new Uint8Array(18) containing the VID bytes.
   */
  toBinary(): Uint8Array {
    return new Uint8Array(this.binary)
  }

  /**
   * Structurally decodes the embedded fields — keyVersion, timestamp,
   * nodeId, sequence.
   *
   * ⚠️  Does NOT verify the signature. For input from an untrusted source,
   *     use vid.parse(), which verifies first.
   *
   * @throws {RangeError} If the embedded timestamp is out of range (corrupt binary).
   */
  parse(): VIDMetadata {
    return decodeMetadata(this.binary)
  }

  /**
   * Byte-for-byte equality with another VIDValue.
   */
  equals(other: VIDValue): boolean {
    if (!(other instanceof VIDValue)) {
      return false
    }
    for (let i = 0; i < VID_BYTE_LENGTH; i++) {
      if (this.binary[i] !== other.binary[i]) {
        return false
      }
    }
    return true
  }

  /**
   * Shows `VIDValue(AEAZY…)` in console.log / util.inspect instead of internals.
   */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `VIDValue(${this.toString()})`
  }

  // ─── Static Factories ───────────────────────────────────────────────────

  /**
   * Constructs a VIDValue from a base32-encoded VID string.
   *
   * Validates format (29 chars, base32 alphabet, canonical padding) before
   * decoding. Case-insensitive; surrounding whitespace is ignored.
   *
   * Use this when receiving a VID from an API request, URL parameter,
   * or any string-based input. After construction, call vid.verify()
   * to authenticate the signature before trusting the ID.
   *
   * @param input - A 29-character base32 VID string.
   * @returns A VIDValue wrapping the decoded binary.
   *
   * @throws {TypeError}  If input is not a string.
   * @throws {RangeError} If input is not exactly 29 characters.
   * @throws {Error}      If input contains invalid or non-canonical base32 characters.
   *
   * @example
   * ```ts
   * const id = VIDValue.fromString("AEAZY4DVF7PQAKQAADFM7JS2DIBBQ")
   * const isValid = vid.verify(id)
   * ```
   */
  static fromString(input: string): VIDValue {
    if (typeof input !== "string") {
      throw new TypeError(
        `VIDValue.fromString: expected a string, received ${typeof input}.`
      )
    }

    const normalized = input.trim().toUpperCase()

    if (normalized.length !== VID_STRING_LENGTH) {
      throw new RangeError(
        `VIDValue.fromString: VID strings must be exactly ${VID_STRING_LENGTH} characters. ` +
        `Received ${normalized.length} characters.`
      )
    }

    if (!VID_STRING_REGEX.test(normalized)) {
      throw new Error(
        `VIDValue.fromString: input contains invalid characters. ` +
        `VID strings use the base32 alphabet (A–Z, 2–7).`
      )
    }

    return new VIDValue(Base32Encoder.decode(normalized))
  }

  /**
   * Constructs a VIDValue from a raw binary buffer.
   *
   * Functionally equivalent to `new VIDValue(binary)` but reads more clearly
   * in pipelines where the input origin is explicit (e.g. database retrieval).
   *
   * @param binary - Raw 18-byte VID binary (Uint8Array or Buffer).
   * @returns A VIDValue wrapping a defensive copy of the binary.
   *
   * @throws {TypeError}  If binary is null, undefined, or not a Uint8Array.
   * @throws {RangeError} If binary is not exactly 18 bytes.
   */
  static fromBinary(binary: Uint8Array): VIDValue {
    return new VIDValue(binary)
  }

  /**
   * Type guard: returns true if the value is a VIDValue instance.
   */
  static isVIDValue(value: unknown): value is VIDValue {
    return value instanceof VIDValue
  }

  /**
   * Comparator for Array.prototype.sort — orders by binary value, which
   * for IDs signed with the same key version is chronological order.
   *
   * @example
   * ```ts
   * ids.sort(VIDValue.compare)
   * ```
   */
  static compare(a: VIDValue, b: VIDValue): number {
    for (let i = 0; i < VID_BYTE_LENGTH; i++) {
      const diff = a.binary[i] - b.binary[i]
      if (diff !== 0) {
        return diff < 0 ? -1 : 1
      }
    }
    return 0
  }
}
