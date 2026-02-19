import { Base32Encoder } from "../encoding/Base32Encoder"

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Required byte length of every VID binary.
 */
const VID_BYTE_LENGTH = 18

/** Required character length of a base32-encoded VID string. */
const VID_STRING_LENGTH = 29

/** Byte offset where the timestamp field begins. */
const OFFSET_TIMESTAMP = 1

/** Byte offset where the nodeId field begins. */
const OFFSET_NODE_ID = 7

/** Byte offset where the sequence field begins. */
const OFFSET_SEQUENCE = 9

/** Byte offset where the HMAC signature begins. */
const OFFSET_SIGNATURE = 11

/**
 * Regex that validates a base32-encoded VID string.
 * Accepts uppercase A–Z and digits 2–7 (standard base32 alphabet), exactly 26 chars.
 */
const VID_STRING_REGEX = /^[A-Z2-7]{26}$/


/**
 * Immutable value object wrapping an 18-byte VID binary.
 *
 * Responsibilities:
 *   - Holds the binary representation as a deeply immutable defensive copy
 *   - Provides string output (base32, 26 chars) via toString()
 *   - Provides binary output (Uint8Array, 18 bytes) via toBinary()
 *   - Exposes structured metadata via parse()
 *   - Supports value equality via equals()
 *   - Validates its own structural integrity on construction
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
 *   - The instance itself is frozen via Object.freeze()
 *   - Cached computed values (string, metadata) are frozen as well
 *
 * Usage:
 *   VIDValue is constructed by VIDGenerator.generate() and VID.parse().
 *   Do not construct directly unless you have a validated 18-byte binary.
 */
export class VIDValue {

  /** Internal 18-byte binary. Never exposed directly — always copied on output. */
  private readonly binary: Uint8Array

  /**
   * Lazily cached base32 string. Computed once on first toString() call.
   * Stored as a non-enumerable property to keep JSON serialization clean.
   */
  private _cachedString?: string

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
        `Ensure this binary was produced by VIDGenerator.generate().`
      )
    }
    this.binary = binary
    this._cachedString = Base32Encoder.encode(this.binary)
  }

  /**
   * Returns the base32-encoded string representation of this VID.
   *
   * Format: 26 uppercase characters from the standard base32 alphabet (A–Z, 2–7).
   * Example: "AEAZY4DVF7PQAKQAAA2PMOJS2DIBB"
   *
   * The result is cached after the first call — subsequent calls return
   * the same string instance with zero re-computation cost.
   *
   * Use cases: APIs, JSON payloads, logging, debugging, URL parameters.
   *
   * @returns 26-character base32 string.
   */
  toString(): string {
    if (this._cachedString !== undefined) {
      return this._cachedString
    }

    const encoded = Base32Encoder.encode(this.binary)

    // direct assignment works because field was never frozen
    this._cachedString = encoded

    return encoded
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

  // ─── Static Factories ───────────────────────────────────────────────────

  /**
   * Constructs a VIDValue from a base32-encoded VID string.
   *
   * Validates format (26 chars, valid base32 alphabet) before decoding.
   * The decoded binary is then validated for correct length.
   *
   * Use this when receiving a VID from an API request, URL parameter,
   * or any string-based input. After construction, call vid.verify()
   * to authenticate the signature before trusting the ID.
   *
   * @param input - A 26-character base32 VID string.
   * @returns A VIDValue wrapping the decoded binary.
   *
   * @throws {TypeError}  If input is not a string.
   * @throws {RangeError} If input is not exactly 26 characters.
   * @throws {Error}      If input contains invalid base32 characters.
   * @throws {RangeError} If the decoded binary is not 18 bytes (corrupt input).
   *
   * @example
   * ```ts
   * const id = VIDValue.fromString("AEAZY4DVF7PQAKQAAA2PMOJS2DIBB")
   * const isValid = vid.verify(id)
   * ```
   */
  static fromString(input: string): VIDValue {
    if (typeof input !== "string") {
      throw new TypeError(
        `VIDValue.fromString: expected a string, received ${typeof input}.`
      )
    }

    const trimmed = input.trim().toUpperCase()

    if (trimmed.length !== VID_STRING_LENGTH) {
      throw new RangeError(
        `VIDValue.fromString: VID strings must be exactly ${VID_STRING_LENGTH} characters. ` +
        `Received ${trimmed.length} characters.`
      )
    }

    if (!VID_STRING_REGEX.test(trimmed)) {
      throw new Error(
        `VIDValue.fromString: input contains invalid characters. ` +
        `VID strings use the base32 alphabet (A–Z, 2–7). ` +
        `Received: "${trimmed}"`
      )
    }

    const binary = Base32Encoder.decode(trimmed)

    // Delegate full binary validation to the constructor
    return new VIDValue(binary)
  }

  /**
   * Constructs a VIDValue from a raw binary buffer, with an explicit type guard.
   *
   * Functionally equivalent to `new VIDValue(binary)` but reads more clearly
   * in pipelines where the input origin is explicit (e.g. database retrieval).
   *
   * @param binary - Raw 18-byte VID binary (Uint8Array or Buffer).
   * @returns A VIDValue wrapping a defensive copy of the binary.
   *
   * @throws {TypeError}  If binary is null, undefined, or not a Uint8Array.
   * @throws {RangeError} If binary is not exactly 18 bytes.
   *
   * @example
   * ```ts
   * // MongoDB
   * const id = VIDValue.fromBinary(doc._id)
   * const isValid = vid.verify(id)
   *
   * // PostgreSQL
   * const id = VIDValue.fromBinary(row.id)
   * ```
   */
  static fromBinary(binary: Uint8Array): VIDValue {
    return new VIDValue(binary)
  }

  /**
   * Type guard: returns true if the value is a valid VIDValue instance.
   *
   * Useful in validation layers, middleware, or any place where you receive
   * an unknown value and need to narrow its type safely.
   *
   * @param value - Any value to test.
   * @returns true if value is a VIDValue, false otherwise.
   *
   * @example
   * ```ts
   * if (VIDValue.isVIDValue(maybeId)) {
   *   const isValid = vid.verify(maybeId)
   * }
   * ```
   */
  static isVIDValue(value: unknown): value is VIDValue {
    return value instanceof VIDValue
  }
}