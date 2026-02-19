/**
 * Parsed metadata extracted from a VID.
 */
export interface VIDMetadata {
  /**
   * Embedded key version used to sign this identifier.
   */
  keyVersion: number

  /**
   * Creation timestamp in milliseconds since Unix epoch.
   * Stored internally as 48-bit integer.
   */
  timestamp: number

  /**
   * JavaScript Date representation of timestamp.
   */
  date: Date

  /**
   * ISO-8601 string representation of timestamp.
   */
  iso: string

  /**
   * Generator node identifier
   */
  nodeId: number

  /**
   * Per-millisecond sequence counter (0–65535).
   */
  sequence: number
}
