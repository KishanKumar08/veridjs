

import { VIDValue } from "../../core/VIDValue"
import { ByteUtils } from "../../utils/ByteUtils"

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────


/** Required byte length of a valid VID binary. */
const VID_BYTE_LENGTH = 18

// ─────────────────────────────────────────────────────────────────────────────
// VIDPostgresAdapter
// ─────────────────────────────────────────────────────────────────────────────

/**
 * PostgreSQL adapter for VID — converts between VID representations and
 * the Node.js Buffer that pg/postgres.js drivers use for BYTEA columns.
 *
 * Why BYTEA instead of TEXT or UUID?
 *
 *   TEXT (base32 string, 29 chars):
 *     29 bytes per row vs 18 bytes per row.
 *     11 bytes × 1M rows = 11MB wasted in index alone.
 *     Requires case-insensitive comparisons (ILIKE, LOWER()).
 *     No meaningful range query support.
 *
 *   UUID (stored as 16-byte pg UUID type):
 *     VID is 18 bytes — does not fit. Forcing it to UUID truncates
 *     2 bytes and destroys the HMAC signature.
 *
 *   BYTEA (correct choice):
 *     Stores exactly 18 bytes. PostgreSQL B-tree index on BYTEA uses
 *     byte-order comparison — since bytes 1–6 are the timestamp,
 *     ORDER BY id ASC sorts chronologically. Queries like
 *     "find all IDs created after X" are native range scans, not full
 *     table scans. This is the same index efficiency as UUIDv7.
 *
 * Schema:
 *   ```sql
 *   CREATE TABLE users (
 *     id    BYTEA PRIMARY KEY,
 *     email TEXT NOT NULL
 *   );
 *
 *   -- Optional: index on timestamp prefix for time-range queries
 *   -- (usually not needed since id IS the primary index)
 *   CREATE INDEX users_created_at ON users (substring(id FROM 2 FOR 6));
 *   ```
 *
 * Driver compatibility:
 *   - pg (node-postgres): BYTEA columns return as Buffer — use fromDatabase()
 *   - postgres.js:        BYTEA columns return as Buffer — use fromDatabase()
 *   - Prisma:             Use Bytes scalar type → Buffer — use fromDatabase()
 *   - Drizzle ORM:        Use blob("id", { mode: "buffer" }) → Buffer — use fromDatabase()
 *
 * Range query pattern (find all IDs created after a timestamp):
 *   ```sql
 *   SELECT * FROM users
 *   WHERE id > $1
 *   ORDER BY id ASC
 *   LIMIT 100;
 *   ```
 *   Pass VIDMongoAdapter.fromString(lastSeenId) as $1 for cursor-based pagination.
 */
export class VIDPostgresAdapter {

  // ─── toDatabase ───────────────────────────────────────────────────────────

  /**
   * Converts a VIDValue or raw Uint8Array to a Buffer for a PostgreSQL BYTEA parameter.
   *
   * Accepts both VIDValue and Uint8Array so callers do not need an extra
   * conversion step:
   *   VIDPostgresAdapter.toDatabase(vid.generate())           // VIDValue directly
   *   VIDPostgresAdapter.toDatabase(vid.generate().toBinary()) // raw Uint8Array
   *
   * Buffer conversion respects byteOffset and byteLength so subarray views
   * (from subarray(), Buffer pool slices) are handled correctly. Without this,
   * a subarray view would produce a Buffer wrapping the full backing ArrayBuffer —
   * potentially thousands of bytes instead of 18, corrupting the stored value.
   *
   * @param input - VIDValue or 18-byte Uint8Array.
   * @returns Buffer suitable for a pg/postgres.js parameterized BYTEA query.
   *
   * @throws {TypeError}  input is not a VIDValue or Uint8Array.
   * @throws {RangeError} Uint8Array is not exactly 18 bytes.
   *
   * @example
   * ```ts
   * // Insert
   * const id = vid.generate()
   * await db.query(
   *   "INSERT INTO users (id, email) VALUES ($1, $2)",
   *   [VIDPostgresAdapter.toDatabase(id), "user@example.com"]
   * )
   *
   * // Query by ID from API request
   * const buffer = VIDPostgresAdapter.fromString(req.params.id)
   * const result = await db.query(
   *   "SELECT * FROM users WHERE id = $1",
   *   [buffer]
   * )
   * ```
   */
  static toDatabase(input: VIDValue | Uint8Array): Buffer {
    const bytes = VIDPostgresAdapter.resolveToBytes(input, "toDatabase")

    // Wrap with explicit byteOffset + byteLength — the correct way to create
    // a Buffer from a Uint8Array that may be a subarray view into a larger
    // ArrayBuffer. Buffer.from(uint8Array) without these args wraps the FULL
    // backing buffer, not just the view's byte range.
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  }

  // ─── fromDatabase ─────────────────────────────────────────────────────────

  /**
   * Converts a Buffer from a PostgreSQL BYTEA column back to a VIDValue.
   *
   * Returns VIDValue (not raw Uint8Array) so callers can immediately use
   * vid.verify(), vid.parse(), id.toString() without an extra conversion step.
   *
   * Validates byte length before constructing VIDValue — rejects corrupt
   * or mistyped columns before they reach verification or parsing.
   *
   * What pg returns for BYTEA:
   *   pg (node-postgres) returns BYTEA columns as Node.js Buffer by default.
   *   If you have custom type parsers that return something else, adapt accordingly.
   *
   * @param buffer - Buffer from a pg/postgres.js BYTEA query result row.
   * @returns VIDValue ready for vid.verify() and vid.parse().
   *
   * @throws {TypeError}  buffer is not a Buffer (or Uint8Array).
   * @throws {RangeError} buffer is not exactly 18 bytes.
   *
   * @example
   * ```ts
   * const result = await db.query("SELECT id, email FROM users WHERE email = $1", [email])
   * const row    = result.rows[0]
   *
   * const id = VIDPostgresAdapter.fromDatabase(row.id)
   *
   * if (!vid.verify(id)) throw new Error("Corrupt row ID")
   *
   * const meta = vid.parse(id, { verify: false }) // already verified above
   * console.log(meta.iso) // "2026-02-18T10:12:34.567Z"
   * ```
   */
  static fromDatabase(buffer: Buffer | Uint8Array): VIDValue {
    // Accept both Buffer and Uint8Array — some drivers and ORMs return
    // BYTEA as a plain Uint8Array rather than a Buffer subclass.
    if (!(buffer instanceof Uint8Array)) {
      throw new TypeError(
        `VIDPostgresAdapter.fromDatabase: expected a Buffer or Uint8Array. ` +
        `Received: ${buffer === null ? "null" : buffer === undefined ? "undefined" : typeof buffer}. ` +
        `Ensure the column is defined as BYTEA and the pg driver is returning binary data.`
      )
    }

    if (buffer.length !== VID_BYTE_LENGTH) {
      throw new RangeError(
        `VIDPostgresAdapter.fromDatabase: BYTEA value must be exactly ${VID_BYTE_LENGTH} bytes. ` +
        `Received ${buffer.length} bytes. ` +
        `This row may be corrupt or the column was not populated using VIDPostgresAdapter.toDatabase().`
      )
    }

    // VIDValue.fromBinary() makes a defensive copy — the returned VIDValue
    // does not share memory with the driver's buffer, which may be pooled
    // or reused across queries.
    return VIDValue.fromBinary(buffer)
  }

  // ─── fromString ───────────────────────────────────────────────────────────

  /**
   * Converts a base32 VID string to a Buffer for use in PostgreSQL query parameters.
   *
   * Use this when you receive a VID string from an API request (URL param,
   * request body, header) and need to query PostgreSQL for the matching row.
   *
   * Validates string format before decoding — rejects malformed input
   * with a clear error before it reaches the database.
   *
   * Note: this does NOT verify the HMAC signature. Call vid.verify() on the
   * returned VIDValue from fromDatabase() if you need to authenticate the ID.
   *
   * @param vidString - Base32-encoded VID string (case-insensitive, trimmable).
   * @returns Buffer suitable for a PostgreSQL BYTEA query parameter.
   *
   * @throws {TypeError}  vidString is not a string.
   * @throws {RangeError} vidString is the wrong length.
   * @throws {Error}      vidString contains invalid base32 characters.
   *
   * @example
   * ```ts
   * // GET /users/:id — query by VID string from URL
   * const buffer = VIDPostgresAdapter.fromString(req.params.id)
   * const result = await db.query(
   *   "SELECT * FROM users WHERE id = $1",
   *   [buffer]
   * )
   * if (result.rows.length === 0) return res.status(404).send()
   *
   * const id = VIDPostgresAdapter.fromDatabase(result.rows[0].id)
   * if (!vid.verify(id)) return res.status(400).send()
   * ```
   */
  static fromString(vidString: string): Buffer {
    // VIDValue.fromString() validates length and charset, then decodes
    const vidValue = VIDValue.fromString(vidString)
    return VIDPostgresAdapter.toDatabase(vidValue)
  }

  // ─── Cursor pagination helper ─────────────────────────────────────────────

  /**
   * Builds a Buffer cursor for PostgreSQL keyset (cursor-based) pagination.
   *
   * Since VID bytes 1–6 are a millisecond timestamp and bytes are in
   * big-endian order, BYTEA comparison (> / <) on the id column is
   * chronologically ordered. This enables efficient cursor pagination
   * without a separate created_at column.
   *
   * @param lastSeenId - The last VID string seen by the client (from previous page).
   * @returns Buffer to use as the $1 parameter in a keyset pagination query.
   *
   * @example
   * ```ts
   * // Client sends: GET /users?after=AEAZY4DVF7PQAKQAAA2PMOJS2DIBB
   * const cursor = VIDPostgresAdapter.toCursor(req.query.after)
   * const result = await db.query(
   *   `SELECT id, email FROM users
   *    WHERE id > $1
   *    ORDER BY id ASC
   *    LIMIT 50`,
   *   [cursor]
   * )
   * const rows = result.rows.map(row => ({
   *   id:    VIDPostgresAdapter.fromDatabase(row.id).toString(),
   *   email: row.email
   * }))
   * ```
   */
  static toCursor(lastSeenId: string): Buffer {
    return VIDPostgresAdapter.fromString(lastSeenId)
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Resolves a VIDValue or Uint8Array input to a validated Uint8Array.
   *
   * Centralises the VIDValue-vs-Uint8Array dispatch and length validation
   * for toDatabase() and any future method that accepts either type.
   *
   * @param input      - VIDValue or raw Uint8Array.
   * @param callerName - Method name for error messages.
   * @returns Validated Uint8Array of exactly VID_BYTE_LENGTH bytes.
   *
   * @throws {TypeError}  input is neither VIDValue nor Uint8Array.
   * @throws {RangeError} Uint8Array is not exactly VID_BYTE_LENGTH bytes.
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
          `VIDPostgresAdapter.${callerName}: Uint8Array must be exactly ${VID_BYTE_LENGTH} bytes. ` +
          `Received ${input.length} bytes. ` +
          `Use vid.generate().toBinary() to produce a valid VID binary.`
        )
      }
      // Defensive copy via ByteUtils.copy() — correctly handles subarray
      // views by respecting byteOffset, unlike new Uint8Array(src.buffer)
      return ByteUtils.copy(input)
    }

    throw new TypeError(
      `VIDPostgresAdapter.${callerName}: input must be a VIDValue or Uint8Array. ` +
      `Received: ${input === null ? "null" : input === undefined ? "undefined" : typeof input}`
    )
  }
}