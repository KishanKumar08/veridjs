import { Binary } from "bson"
import { VIDValue } from "../../core/VIDValue"
import { ByteUtils } from "../../utils/ByteUtils"


/**
 * Required byte length of a valid VID binary.
 * Validated on every toDatabase() call so corrupt data is rejected early,
 * not at query time or during verification.
 */
const VID_BYTE_LENGTH = 18

/**
 * BSON Binary subtype for user-defined binary data.
 * Subtype 0x00 is the generic binary subtype — correct for arbitrary byte arrays.
 * Do not use subtype 3 or 4 (UUID subtypes) — VID is not a UUID.
 *
 * MongoDB stores BSON Binary as { $binary: { base64: "...", subType: "00" } }
 * in extended JSON. Using the correct subtype ensures round-trip fidelity
 * and correct behavior with MongoDB drivers that inspect subtype.
 */
const BSON_BINARY_SUBTYPE = 0

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Shape of a MongoDB document field storing a VID.
 * Use this as the type for your Mongoose schema or native driver documents.
 *
 * @example
 * ```ts
 * interface UserDocument {
 *   _id: VIDDocument
 *   email: string
 * }
 * ```
 */
export type VIDDocument = Binary

// ─────────────────────────────────────────────────────────────────────────────
// VIDMongoAdapter
// ─────────────────────────────────────────────────────────────────────────────

/**
 * MongoDB adapter for VID — converts between VID representations and
 * the BSON Binary type that MongoDB stores efficiently.
 *
 * Why BSON Binary instead of Buffer or string?
 *
 *   Buffer (raw bytes):
 *     MongoDB drivers accept raw Buffer, but they store it as BSON Binary
 *     internally anyway. Wrapping in Binary explicitly makes the subtype
 *     visible, prevents accidental string coercion, and makes schema
 *     intent clear to other developers reading the code.
 *
 *   String (base32 VID string):
 *     26-char string stored as UTF-8 = 26 bytes on disk.
 *     BSON Binary = 18 bytes on disk.
 *     At 1 million documents: 8MB wasted in index alone.
 *     Strings also lose type information and require special handling
 *     to avoid case-sensitivity issues in queries.
 *
 *   BSON Binary (correct choice):
 *     18 bytes, correct subtype, efficient B-tree indexing,
 *     no encoding ambiguity, preserves byte order for range queries.
 *
 * Index performance:
 *   VID binaries are time-prefixed (bytes 1–6 are the timestamp).
 *   MongoDB's B-tree index on a Binary _id field will have excellent
 *   insert locality — new documents append near the end of the index
 *   rather than scattering across it like UUIDv4. This matches the
 *   performance characteristics of UUIDv7 and Snowflake IDs.
 *
 * Setup:
 *   ```ts
 *   // Mongoose schema
 *   const userSchema = new Schema({
 *     _id: { type: Buffer, default: () => VIDMongoAdapter.toDatabase(vid.generate()) }
 *   })
 *
 *   // Native driver
 *   await collection.insertOne({
 *     _id: VIDMongoAdapter.toDatabase(vid.generate())
 *   })
 *   ```
 *
 * Query pattern:
 *   ```ts
 *   const binary = VIDMongoAdapter.fromString("AEAZY4DVF7PQAKQAAA2PMOJS2DIBB")
 *   const doc    = await collection.findOne({ _id: binary })
 *   ```
 */
export class VIDMongoAdapter {

  // ─── toDatabase ───────────────────────────────────────────────────────────

  /**
   * Converts a VIDValue or raw Uint8Array to a BSON Binary for database storage.
   *
   * BSON Binary subtype 0x00 (generic binary) is used — correct for VID.
   * The MongoDB driver stores this as an efficient 18-byte binary field.
   *
   * Accepts both VIDValue and raw Uint8Array so callers can write:
   *   VIDMongoAdapter.toDatabase(vid.generate())        // VIDValue directly
   *   VIDMongoAdapter.toDatabase(vid.generate().toBinary()) // raw bytes
   *
   * Buffer conversion:
   *   Uses byteOffset and byteLength explicitly to handle Uint8Array views
   *   (subarray slices, Buffer pool allocations). Without this, a subarray
   *   view would produce a Buffer wrapping the FULL backing ArrayBuffer —
   *   which could be thousands of bytes instead of 18.
   *
   * @param input - VIDValue or 18-byte Uint8Array from vid.generate().toBinary().
   * @returns BSON Binary ready to store as a MongoDB document field.
   *
   * @throws {TypeError}  input is not a VIDValue or Uint8Array.
   * @throws {RangeError} Uint8Array is not exactly 18 bytes.
   *
   * @example
   * ```ts
   * const id  = vid.generate()
   * const doc = { _id: VIDMongoAdapter.toDatabase(id), email: "user@example.com" }
   * await collection.insertOne(doc)
   * ```
   */
  static toDatabase(input: VIDValue | Uint8Array): Binary {
    const bytes = VIDMongoAdapter.resolveToBytes(input, "toDatabase")

    // Wrap in Buffer with explicit byteOffset + byteLength.
    // This is the correct way to create a Buffer from a Uint8Array view —
    // it copies exactly the bytes the view represents, not its full backing buffer.
    const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)

    return new Binary(buffer, BSON_BINARY_SUBTYPE)
  }

  // ─── fromDatabase ─────────────────────────────────────────────────────────

  /**
   * Converts a BSON Binary retrieved from MongoDB back to a VIDValue.
   *
   * Returns a VIDValue rather than a raw Uint8Array so callers can
   * immediately call vid.verify(), vid.parse(), id.toString(), etc.
   * without an extra conversion step.
   *
   * Validates byte length on input — rejects corrupt or wrong-typed
   * documents before they reach verification or parsing.
   *
   * @param value - BSON Binary from a MongoDB document field.
   * @returns VIDValue wrapping the stored binary.
   *
   * @throws {TypeError}  value is not a BSON Binary instance.
   * @throws {RangeError} Binary buffer is not exactly 18 bytes.
   *
   * @example
   * ```ts
   * const doc = await collection.findOne({ email: "user@example.com" })
   * const id  = VIDMongoAdapter.fromDatabase(doc._id)
   *
   * if (!vid.verify(id)) throw new Error("Corrupt document ID")
   *
   * const meta = vid.parse(id, { verify: false }) // already verified above
   * console.log(meta.iso) // "2026-02-18T10:12:34.567Z"
   * ```
   */
  static fromDatabase(value: Binary): VIDValue {
    if (!(value instanceof Binary)) {
      throw new TypeError(
        `VIDMongoAdapter.fromDatabase: expected a BSON Binary instance. ` +
        `Received: ${value === null ? "null" : value === undefined ? "undefined" : typeof value}. ` +
        `Ensure the field was stored using VIDMongoAdapter.toDatabase().`
      )
    }

    // Binary.buffer is a Node.js Buffer — always a fresh allocation from BSON,
    // not a pooled view, so byteOffset is reliably 0. We still go through
    // VIDValue.fromBinary() to get length validation and a defensive copy.
    const bytes = new Uint8Array(value.buffer)

    if (bytes.length !== VID_BYTE_LENGTH) {
      throw new RangeError(
        `VIDMongoAdapter.fromDatabase: BSON Binary must be exactly ${VID_BYTE_LENGTH} bytes. ` +
        `Received ${bytes.length} bytes. ` +
        `This document field may be corrupt or was not stored as a VID.`
      )
    }

    return VIDValue.fromBinary(bytes)
  }

  // ─── fromString ───────────────────────────────────────────────────────────

  /**
   * Converts a base32 VID string directly to a BSON Binary for use in queries.
   *
   * Use this when you receive a VID string (from an API request, URL param,
   * or client payload) and need to query MongoDB for it. This avoids the
   * two-step pattern of parsing a string to VIDValue then converting to Binary.
   *
   * The string is validated (length, charset) before decoding.
   * Verification is NOT performed here — call vid.verify() separately
   * if you need to authenticate the ID before querying.
   *
   * @param vidString - Base32-encoded VID string (case-insensitive).
   * @returns BSON Binary suitable for a MongoDB query filter.
   *
   * @throws {TypeError}  vidString is not a string.
   * @throws {RangeError} vidString is the wrong length.
   * @throws {Error}      vidString contains invalid base32 characters.
   *
   * @example
   * ```ts
   * // In a REST handler — query by ID from URL param
   * const binary = VIDMongoAdapter.fromString(req.params.id)
   * const doc    = await collection.findOne({ _id: binary })
   * if (!doc) return res.status(404).send()
   *
   * const id = VIDMongoAdapter.fromDatabase(doc._id)
   * if (!vid.verify(id)) return res.status(400).send()
   * ```
   */
  static fromString(vidString: string): Binary {
    // VIDValue.fromString() validates format (length, charset) and decodes
    const vidValue = VIDValue.fromString(vidString)
    return VIDMongoAdapter.toDatabase(vidValue)
  }

  // ─── toVIDValue ───────────────────────────────────────────────────────────

  /**
   * Converts a BSON Binary to a VIDValue without going through fromDatabase().
   *
   * Alias for fromDatabase() with a more explicit name — use whichever
   * reads more clearly in context. Both are identical in behavior.
   *
   * @param binary - BSON Binary from a MongoDB document.
   * @returns VIDValue for verification and parsing.
   */
  static toVIDValue(binary: Binary): VIDValue {
    return VIDMongoAdapter.fromDatabase(binary)
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Resolves a VIDValue or Uint8Array input to a validated Uint8Array.
   *
   * Centralises the VIDValue-vs-Uint8Array dispatch for toDatabase() and
   * any future method that accepts either type. Validates byte length in
   * both cases.
   *
   * @param input     - VIDValue or raw Uint8Array.
   * @param callerName - Method name for error messages.
   * @returns Validated Uint8Array of exactly VID_BYTE_LENGTH bytes.
   *
   * @throws {TypeError}  input is not a VIDValue or Uint8Array.
   * @throws {RangeError} Uint8Array is not VID_BYTE_LENGTH bytes.
   */
  private static resolveToBytes(
    input: VIDValue | Uint8Array,
    callerName: string
  ): Uint8Array {
    if (input instanceof VIDValue) {
      // toBinary() always returns a fresh 18-byte defensive copy
      return input.toBinary()
    }

    if (input instanceof Uint8Array) {
      if (input.length !== VID_BYTE_LENGTH) {
        throw new RangeError(
          `VIDMongoAdapter.${callerName}: Uint8Array must be exactly ${VID_BYTE_LENGTH} bytes. ` +
          `Received ${input.length} bytes. ` +
          `Use vid.generate().toBinary() to produce a valid VID binary.`
        )
      }
      // Return a defensive copy via ByteUtils.copy() which correctly handles
      // subarray views (respects byteOffset, does not wrap full backing buffer)
      return ByteUtils.copy(input)
    }

    throw new TypeError(
      `VIDMongoAdapter.${callerName}: input must be a VIDValue or Uint8Array. ` +
      `Received: ${input === null ? "null" : input === undefined ? "undefined" : typeof input}`
    )
  }
}