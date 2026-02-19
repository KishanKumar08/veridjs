import { VIDMetadata } from "../types"
import { VIDValue } from "./VIDValue"
import { Base32Encoder } from "../encoding/Base32Encoder"

/** Total byte length of a valid VID binary. */
const VID_BYTE_LENGTH = 18

/** Character length of a base32-encoded VID string. */
const VID_STRING_LENGTH = 29

/**
 * Byte offsets for each field in the VID binary layout.
 *
 *   ┌────────────┬───────────┬────────┬──────────┬───────────┐
 *   │ KeyVersion │ Timestamp │ NodeId │ Sequence │ Signature │
 *   │  [0]  1B   │ [1–6] 6B  │[7–8]2B │[9–10] 2B │[11–17]7B  │
 *   └────────────┴───────────┴────────┴──────────┴───────────┘
 */
const OFFSET_KEY_VERSION = 0
const OFFSET_TIMESTAMP_HIGH = 1  // uint32 — high 32 bits of the 48-bit timestamp
const OFFSET_TIMESTAMP_LOW = 5   // uint16 — low  16 bits of the 48-bit timestamp
const OFFSET_NODE_ID = 7
const OFFSET_SEQUENCE = 9

/**
 * Multiplier to reconstruct the 48-bit timestamp from its two stored parts.
 * timestamp = (high * 0x10000) + low
 */
const TIMESTAMP_HIGH_MULTIPLIER = 0x10000 // 65536

/**
 * Maximum valid Unix millisecond timestamp this parser will accept.
 * Matches the 48-bit ceiling used at generation time (~year 10895 CE).
 */
const MAX_TIMESTAMP = 0xffffffffffff

/**
 * Minimum sane Unix millisecond timestamp.
 * Set to 2020-01-01T00:00:00.000Z to reject accidental zero timestamps,
 * corrupted data, or test fixtures that forgot to set the time.
 * Adjust if your system predates this (unlikely for a new project).
 */
const MIN_TIMESTAMP = 1577836800000 // 2020-01-01T00:00:00.000Z

/** Valid base32 alphabet: uppercase A–Z and digits 2–7. */
const BASE32_REGEX = /^[A-Z2-7]{29}$/

// ─────────────────────────────────────────────────────────────────────────────
// VIDParser
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parses a VID into its structured metadata fields.
 *
 * Accepts all VID representations and decodes the binary layout into a
 * typed VIDMetadata object. This is a pure structural decode — it does NOT
 * verify the HMAC signature. Always call vid.verify() before calling parse()
 * on input from an untrusted source.
 *
 * Note:
 *   Parsing does not authenticate the VID. A forged or tampered VID will
 *   parse successfully — it just won't verify. The canonical safe pattern is:
 *
 *     const isValid = vid.verify(input)
 *     if (!isValid) throw new Error("Untrusted VID")
 *     const meta = VIDParser.parse(input)
 *
 * Accepted input types:
 *   - string     → base32-encoded 26-char VID ("AEAZY4DVF7PQAKQAAA2PMOJS2DIBB")
 *   - Uint8Array → raw 18-byte binary
 *   - Buffer     → Node.js Buffer (subclass of Uint8Array)
 *   - ArrayBuffer → raw ArrayBuffer (Web / edge environments)
 *   - VIDValue   → first-class VID object
 */
export class VIDParser {

  /**
   * Parses a VID into its structured VIDMetadata.
   *
   * @param input - VID in any accepted representation.
   * @returns Frozen VIDMetadata with keyVersion, timestamp, date, iso, nodeId, sequence.
   *
   * @throws {TypeError}  Input is null, undefined, or an unsupported type.
   * @throws {RangeError} Binary is not exactly 18 bytes.
   * @throws {RangeError} String is not exactly 26 characters.
   * @throws {Error}      String contains invalid base32 characters.
   * @throws {Error}      Base32 decoding fails unexpectedly.
   * @throws {RangeError} Decoded timestamp is outside the valid range
   *                      (MIN_TIMESTAMP – MAX_TIMESTAMP).
   * @throws {Error}      Timestamp cannot be represented as a valid ISO date.
   *
   * @example
   * ```ts
   * // Always verify before parsing untrusted input
   * if (!vid.verify(input)) throw new Error("Invalid VID")
   * const meta = VIDParser.parse(input)
   *
   * console.log(meta.iso)       // "2026-02-18T10:12:34.567Z"
   * console.log(meta.nodeId)    // 42
   * console.log(meta.sequence)  // 7
   * console.log(meta.keyVersion) // 1
   * ```
   */
  static parse(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue
  ): VIDMetadata {

    // Normalize to binary — throws with precise messages on failure
    const binary = VIDParser.normalizeToBinary(input)

    // Validate binary length post-normalization
    if (binary.length !== VID_BYTE_LENGTH) {
      throw new RangeError(
        `VIDParser: binary must be exactly ${VID_BYTE_LENGTH} bytes. ` +
        `Decoded ${binary.length} bytes. ` +
        `Ensure the input was produced by VIDGenerator.generate().`
      )
    }

    // Create a DataView anchored to the exact byte range.
    const view = new DataView(
      binary.buffer,
      binary.byteOffset,
      binary.byteLength
    )

    // Decode keyVersion — byte 0, uint8
    const keyVersion = view.getUint8(OFFSET_KEY_VERSION)

    // Decode timestamp — 48 bits stored as uint32 (high) + uint16 (low)
    const timestampHigh = view.getUint32(OFFSET_TIMESTAMP_HIGH)
    const timestampLow = view.getUint16(OFFSET_TIMESTAMP_LOW)
    const timestamp = timestampHigh * TIMESTAMP_HIGH_MULTIPLIER + timestampLow

    // Validate timestamp is within the expected range
    if (!Number.isSafeInteger(timestamp)) {
      throw new RangeError(
        `VIDParser: decoded timestamp (${timestamp}) is not a safe integer. ` +
        `The binary may be corrupt.`
      )
    }

    if (timestamp < MIN_TIMESTAMP || timestamp > MAX_TIMESTAMP) {
      throw new RangeError(
        `VIDParser: decoded timestamp (${timestamp}) is outside the valid range ` +
        `[${MIN_TIMESTAMP} (2020-01-01) – ${MAX_TIMESTAMP} (~year 10895)]. ` +
        `The binary may be corrupt or from an untrusted source.`
      )
    }

    // Decode nodeId — bytes 7–8, uint16
    const nodeId = view.getUint16(OFFSET_NODE_ID)

    // Decode sequence — bytes 9–10, uint16
    const sequence = view.getUint16(OFFSET_SEQUENCE)

    // Derive Date from embedded timestamp — NOT from Date.now()
    const date = new Date(timestamp)

    // Compute ISO string — validate the Date is representable
    let iso: string
    try {
      iso = date.toISOString()
    } catch {
      throw new Error(
        `VIDParser: timestamp (${timestamp}) cannot be represented as an ISO date. ` +
        `This should not occur after range validation — the binary may be corrupt.`
      )
    }

    // Return a frozen metadata object.
    return Object.freeze({
      keyVersion,
      timestamp,
      date,
      iso,
      nodeId,
      sequence,
    })
  }


  /**
   * Normalizes any accepted VID input type to a raw Uint8Array binary.
   *
   * Throws descriptive errors for all invalid inputs — unlike VIDVerifier
   * which returns false silently. The parser is called intentionally with
   * valid data; a parse failure is a programming error that deserves a
   * clear message, not a silent false.
   *
   * Input handling notes:
   *   VIDValue   → checked first (it IS a Uint8Array wrapper; must handle via public API)
   *   Buffer     → checked before Uint8Array (Buffer extends Uint8Array; different handling)
   *   Uint8Array → used as-is (no copy; parser is read-only, no mutation risk)
   *   ArrayBuffer → wrapped in a Uint8Array view (no copy)
   *   string     → uppercased, trimmed, validated, then base32-decoded
   */
  private static normalizeToBinary(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue
  ): Uint8Array {

    // ── null / undefined ────────────────────────────────────────────────────
    if (input === null || input === undefined) {
      throw new TypeError(
        `VIDParser: input is required. ` +
        `Received: ${input === null ? "null" : "undefined"}`
      )
    }

    if (input instanceof VIDValue) {
      return input.toBinary()
    }

    if (typeof Buffer !== "undefined" && Buffer.isBuffer(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
    }

    // ── Uint8Array ───────────────────────────────────────────────────────────
    if (input instanceof Uint8Array) {
      return input
    }

    // ── ArrayBuffer ──────────────────────────────────────────────────────────
    if (input instanceof ArrayBuffer) {
      return new Uint8Array(input)
    }

    // ── string ───────────────────────────────────────────────────────────────
    if (typeof input === "string") {
      return VIDParser.decodeString(input)
    }

    // ── Unsupported ──────────────────────────────────────────────────────────
    throw new TypeError(
      `VIDParser: unsupported input type "${typeof input}". ` +
      `Accepted: string, Uint8Array, Buffer, ArrayBuffer, VIDValue.`
    )
  }

  /**
   * Validates and decodes a base32-encoded VID string to its binary form.
   *
   * Validation order matters — cheapest checks run first:
   *   1. Length check (O(1)) — rejects most garbage immediately
   *   2. Charset check (O(n) regex) — catches invalid alphabet before decode
   *   3. Decode (O(n)) — only runs on structurally plausible strings
   *
   * @param input - Raw string input from the caller (not yet trimmed or uppercased).
   * @returns Decoded 18-byte Uint8Array.
   *
   * @throws {RangeError} String is not exactly 26 characters after trim.
   * @throws {Error}      String contains characters outside the base32 alphabet.
   * @throws {Error}      Base32 decoding fails unexpectedly.
   */
  private static decodeString(input: string): Uint8Array {
    const normalized = input.trim().toUpperCase()

    if (normalized.length !== VID_STRING_LENGTH) {
      throw new RangeError(
        `VIDParser: VID strings must be exactly ${VID_STRING_LENGTH} characters. ` +
        `Received ${normalized.length} characters: "${input.trim()}"`
      )
    }

    if (!BASE32_REGEX.test(normalized)) {
      throw new Error(
        `VIDParser: VID string contains invalid characters. ` +
        `Only base32 characters (A–Z, 2–7) are allowed. ` +
        `Received: "${normalized}"`
      )
    }

    try {
      return Base32Encoder.decode(normalized)
    } catch (err) {
      throw new Error(
        `VIDParser: base32 decoding failed unexpectedly for input "${normalized}". ` +
        `Cause: ${err instanceof Error ? err.message : String(err)}`
      )
    }
  }
}