import { VIDMetadata } from "../types"
import { decodeMetadata } from "./metadata"
import { InputFailureReason, normalizeInput, VIDInput } from "./input"

/**
 * Parses a VID into its structured metadata fields.
 *
 * This is a pure structural decode — it does NOT verify the HMAC signature.
 * A forged or tampered VID will parse successfully; it just won't verify.
 * vid.parse() verifies first; use VIDParser directly only on trusted input.
 *
 * Accepted input types:
 *   - string      → base32-encoded 29-char VID ("AEAZY4DVF7PQAKQAADFM7JS2DIBBQ")
 *   - Uint8Array  → raw 18-byte binary (Buffer included)
 *   - ArrayBuffer → raw ArrayBuffer (Web / edge environments)
 *   - VIDValue    → first-class VID object
 */
export class VIDParser {

  /**
   * Parses a VID into its structured VIDMetadata.
   *
   * @param input - VID in any accepted representation.
   * @returns Frozen VIDMetadata with keyVersion, timestamp, date, iso, nodeId, sequence.
   *
   * @throws {TypeError}  Input is null, undefined, or an unsupported type.
   * @throws {RangeError} Binary is not 18 bytes, string is not 29 characters,
   *                      or the decoded timestamp is out of range.
   * @throws {Error}      String contains invalid or non-canonical base32 characters.
   */
  static parse(input: VIDInput): VIDMetadata {
    const normalized = normalizeInput(input)

    if (!normalized.ok) {
      throw VIDParser.errorFor(normalized.reason)
    }

    return decodeMetadata(normalized.binary)
  }

  private static errorFor(reason: InputFailureReason): Error {
    const message = `VIDParser: cannot parse input (${reason}). `
    switch (reason) {
      case "NULL_INPUT":
      case "UNSUPPORTED_TYPE":
        return new TypeError(
          message + `Accepted: string, Uint8Array, Buffer, ArrayBuffer, VIDValue.`
        )
      case "INVALID_STRING_LENGTH":
      case "INVALID_BINARY_LENGTH":
        return new RangeError(
          message + `VIDs are 18 bytes, or 29 characters as a base32 string.`
        )
      default:
        return new Error(message + `VID strings use the base32 alphabet (A–Z, 2–7).`)
    }
  }
}
