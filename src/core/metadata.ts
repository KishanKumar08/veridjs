import { VIDMetadata } from "../types"

/**
 * Byte offsets of each field inside an 18-byte VID binary.
 *   [keyVersion:1][timestamp:6][nodeId:2][sequence:2][signature:7]
 */
const OFFSET_KEY_VERSION = 0
const OFFSET_TIMESTAMP_HIGH = 1  // uint32 — high 32 bits of the 48-bit timestamp
const OFFSET_TIMESTAMP_LOW = 5   // uint16 — low  16 bits of the 48-bit timestamp
const OFFSET_NODE_ID = 7
const OFFSET_SEQUENCE = 9

const TIMESTAMP_HIGH_MULTIPLIER = 0x10000 // 65536

/** Upper bound of the 48-bit timestamp field (~year 10895 CE). */
const MAX_TIMESTAMP = 0xffffffffffff

/**
 * Lower bound for a plausible VID timestamp: 2020-01-01T00:00:00.000Z.
 * Anything earlier predates the format and indicates corrupt input.
 */
const MIN_TIMESTAMP = 1577836800000

/**
 * Structurally decodes the fields of an 18-byte VID binary.
 * Does NOT verify the signature — callers decide whether that is needed.
 *
 * @param binary - Exactly 18 bytes (length is the caller's responsibility).
 * @returns Frozen VIDMetadata.
 *
 * @throws {RangeError} If the embedded timestamp is outside [2020-01-01, MAX_TIMESTAMP].
 */
export function decodeMetadata(binary: Uint8Array): VIDMetadata {
  const view = new DataView(binary.buffer, binary.byteOffset, binary.byteLength)

  const keyVersion = view.getUint8(OFFSET_KEY_VERSION)
  const timestamp =
    view.getUint32(OFFSET_TIMESTAMP_HIGH) * TIMESTAMP_HIGH_MULTIPLIER +
    view.getUint16(OFFSET_TIMESTAMP_LOW)

  // 48-bit values are always safe integers; only the range needs checking.
  if (timestamp < MIN_TIMESTAMP || timestamp > MAX_TIMESTAMP) {
    throw new RangeError(
      `VIDParser: decoded timestamp (${timestamp}) is outside the valid range ` +
      `[${MIN_TIMESTAMP} (2020-01-01) – ${MAX_TIMESTAMP} (~year 10895)]. ` +
      `The binary may be corrupt or from an untrusted source.`
    )
  }

  const date = new Date(timestamp)

  return Object.freeze({
    keyVersion,
    timestamp,
    date,
    iso: date.toISOString(),
    nodeId: view.getUint16(OFFSET_NODE_ID),
    sequence: view.getUint16(OFFSET_SEQUENCE),
  })
}
