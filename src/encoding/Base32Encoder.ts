/**
 * Standard RFC 4648 base32 alphabet.
 * 32 characters: uppercase A–Z (26) + digits 2–7 (6).
 *
 * Digits 0 and 1 are intentionally excluded:
 *   0 is visually ambiguous with O (letter O)
 *   1 is visually ambiguous with I (letter I) and l (lowercase L)
 *
 * This makes base32 strings human-readable and safe to copy by hand,
 * which matters when VID strings appear in logs, URLs, or support tickets.
 */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/**
 * Number of bits encoded per base32 character.
 * Each character represents one of 32 values → log2(32) = 5 bits.
 */
const BITS_PER_CHAR = 5

/**
 * Number of bits in a byte.
 */
const BITS_PER_BYTE = 8

/**
 * Byte length of a VID binary.
 * 18 bytes of input → base32 encoded output.
 */
const VID_BINARY_BYTES = 18

/**
 * Character length of a base32-encoded VID string.
 *
 * Derivation:
 *   18 bytes × 8 bits/byte = 144 bits of input
 *   144 bits ÷ 5 bits/char = 28.8 chars → rounds up to 29?

 *   Standard RFC 4648 base32 pads to multiples of 8 characters using '='.
 *   VID uses unpadded base32 (no '=' characters), which is common in
 *   URL-safe and compact encoding contexts.
 *
 *   Unpadded length = ceil(inputBytes * 8 / 5)
 *   ceil(18 * 8 / 5) = ceil(144 / 5) = ceil(28.8) = 29 characters
 *
 *   Let's compute carefully for common byte lengths:
 *     18 bytes → ceil(144/5) = ceil(28.8) = 29 chars
 *
 *   Conclusion: 18 bytes encodes to 29 base32 characters
 * 
 * Do not change this constant in isolation without changing VID_BINARY_BYTES.
 */
const VID_STRING_CHARS = Math.ceil((VID_BINARY_BYTES * BITS_PER_BYTE) / BITS_PER_CHAR)
// = Math.ceil(144 / 5) = Math.ceil(28.8) = 29

/**
 * Bitmask to extract the low BITS_PER_CHAR bits from an accumulated value.
 * 0b11111 = 31 = 2^5 - 1
 */
const CHAR_MASK = (1 << BITS_PER_CHAR) - 1

/**
 * Bitmask to extract the low 8 bits from an accumulated value.
 */
const BYTE_MASK = (1 << BITS_PER_BYTE) - 1

/**
 * Maximum ASCII code point that can be in a valid base32 character.
 * Used to bounds-check before accessing the lookup table.
 * '7' has char code 55; all base32 chars are ASCII and fit in 7 bits.
 */
const MAX_ASCII = 127

// ─────────────────────────────────────────────────────────────────────────────
// Base32Encoder
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Unpadded RFC 4648 base32 encoder and decoder for VID binaries.
 *
 * Encodes 18-byte VID binaries to 29-character base32 strings.
 * Decodes 29-character base32 strings back to 18-byte binaries.
 *
 * Design:
 *   - No padding characters ('=') — compact output, simpler parsing
 *   - Uppercase only — consistent with VID string format
 *   - Decode accepts mixed case (normalized to uppercase internally)
 *   - Lookup table for O(1) character → value mapping during decode
 *   - All outputs are fresh Uint8Array allocations — callers own them
 *
 * Why base32 over base64?
 *   Base64 uses '+', '/', and '=' which are not URL-safe without encoding.
 *   Base32 uses only alphanumerics (A–Z, 2–7) — safe in URLs, filenames,
 *   log lines, and human-readable contexts without escaping.
 *   The cost is ~16% longer strings (29 chars vs 24 chars for 18 bytes).
 */
export class Base32Encoder {
  /**
   * Decode lookup table: ASCII char code → base32 value (0–31).
   * Entries are -1 for characters not in the base32 alphabet.
   *
   * Int16Array (not Uint8Array) because -1 must be representable.
   * Size is MAX_ASCII + 1 (128 entries) — one slot per 7-bit ASCII code point.
   *
   * Built once at class load time and reused across all calls.
   * This makes decode O(n) in input length with zero per-call setup cost.
   */
  private static readonly DECODE_LOOKUP: Int16Array = (() => {
    const table = new Int16Array(MAX_ASCII + 1).fill(-1)

    for (let i = 0; i < ALPHABET.length; i++) {
      table[ALPHABET.charCodeAt(i)] = i
    }

    return table
  })()

  /**
   * Encodes an 18-byte VID binary to a 29-character unpadded base32 string.
   *
   * Algorithm:
   *   Treats the input as a stream of bits. Accumulates bits into a buffer.
   *   When the buffer has ≥5 bits, emit one base32 character (the high 5 bits).
   *   After all bytes, if leftover bits remain, zero-pad to 5 bits and emit.
   *
   * @param input - 18-byte Uint8Array to encode.
   * @returns 29-character uppercase base32 string.
   *
   * @throws {TypeError}  input is not a Uint8Array.
   * @throws {RangeError} input is not exactly VID_BINARY_BYTES bytes.
   */
  static encode(input: Uint8Array): string {
    if (!(input instanceof Uint8Array)) {
      throw new TypeError(
        `Base32Encoder.encode: input must be a Uint8Array. Received: ${typeof input}`
      )
    }

    if (input.length !== VID_BINARY_BYTES) {
      throw new RangeError(
        `Base32Encoder.encode: input must be exactly ${VID_BINARY_BYTES} bytes. ` +
        `Received ${input.length} bytes.`
      )
    }

    let bits = 0    // number of valid bits currently accumulated in value
    let value = 0   // bit accumulator
    let output = "" // result string (29 chars; string concat is fast for short strings)

    for (let i = 0; i < input.length; i++) {
      // Shift existing bits left by 8, then OR in the new byte
      value = (value << BITS_PER_BYTE) | input[i]
      bits += BITS_PER_BYTE

      // Emit one base32 character for every 5 accumulated bits
      while (bits >= BITS_PER_CHAR) {
        bits -= BITS_PER_CHAR
        output += ALPHABET[(value >>> bits) & CHAR_MASK]
      }
    }

    // Emit final character for any remaining bits (zero-padded to 5 bits)
    if (bits > 0) {
      output += ALPHABET[(value << (BITS_PER_CHAR - bits)) & CHAR_MASK]
    }

    return output
  }

  /**
   * Decodes a 29-character unpadded base32 string to an 18-byte Uint8Array.
   *
   * Accepts mixed case — input is normalized to uppercase before processing.
   * Leading and trailing whitespace is stripped.
   *
   * Algorithm:
   *   For each character, look up its 5-bit value via DECODE_LOOKUP.
   *   Accumulate bits into a buffer. When the buffer has ≥8 bits,
   *   emit one byte (the high 8 bits). Remaining bits after all chars
   *   are zero-padding from the encoder — discard them.
   *
   * @param input - 29-character base32 string (case-insensitive, trimmable).
   * @returns 18-byte Uint8Array containing the decoded binary.
   *
   * @throws {TypeError}  input is not a string.
   * @throws {RangeError} input is not exactly VID_STRING_CHARS characters after normalization.
   * @throws {Error}      input contains a character outside the base32 alphabet.
   * @throws {RangeError} decoded output is not exactly VID_BINARY_BYTES bytes (sanity check).
   */
  static decode(input: string): Uint8Array {
    if (typeof input !== "string") {
      throw new TypeError(
        `Base32Encoder.decode: input must be a string. Received: ${typeof input}`
      )
    }

    const normalized = input.trim().toUpperCase()

    if (normalized.length !== VID_STRING_CHARS) {
      throw new RangeError(
        `Base32Encoder.decode: input must be exactly ${VID_STRING_CHARS} characters ` +
        `after trimming. Received ${normalized.length} characters. ` +
        `A ${VID_BINARY_BYTES}-byte VID binary always encodes to ${VID_STRING_CHARS} base32 characters.`
      )
    }

    let bits = 0    // number of valid bits currently accumulated in value
    let value = 0   // bit accumulator

    const output = new Uint8Array(VID_BINARY_BYTES)
    let outputIndex = 0

    for (let i = 0; i < normalized.length; i++) {
      const charCode = normalized.charCodeAt(i)

      // Reject non-ASCII — our lookup table only covers 0–127
      if (charCode > MAX_ASCII) {
        throw new Error(
          `Base32Encoder.decode: invalid character at position ${i}: ` +
          `"${normalized[i]}" (code ${charCode}). ` +
          `Only base32 characters (A–Z, 2–7) are valid.`
        )
      }

      const charValue = Base32Encoder.DECODE_LOOKUP[charCode]

      if (charValue === -1) {
        throw new Error(
          `Base32Encoder.decode: invalid base32 character at position ${i}: ` +
          `"${normalized[i]}". Valid characters are A–Z and 2–7.`
        )
      }

      // Accumulate 5 bits from this character
      value = (value << BITS_PER_CHAR) | charValue
      bits += BITS_PER_CHAR

      // Emit one byte for every 8 accumulated bits
      if (bits >= BITS_PER_BYTE) {
        bits -= BITS_PER_BYTE
        output[outputIndex++] = (value >>> bits) & BYTE_MASK
      }
    }

    // Sanity check: output must be exactly VID_BINARY_BYTES.
    // This should never fail given correct VID_STRING_CHARS and VID_BINARY_BYTES,
    if (outputIndex !== VID_BINARY_BYTES) {
      throw new RangeError(
        `Base32Encoder.decode: internal error — expected ${VID_BINARY_BYTES} output bytes ` +
        `but produced ${outputIndex}. This indicates a mismatch between ` +
        `VID_BINARY_BYTES and VID_STRING_CHARS constants.`
      )
    }

    return output
  }
}