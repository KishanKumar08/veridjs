import { ByteUtils } from "../utils/ByteUtils"
import { HMACSigner } from "../crypto/HMACSigner"
import { VIDValue } from "./VIDValue"
import { TimeUtils } from "../utils/TimeUtils"
import * as crypto from "crypto"

/**
 * Maximum millisecond timestamp representable in 6 bytes (48 bits).
 * Equivalent to year ~10895 CE. Safe for all practical lifetimes.
 */
const MAX_TIMESTAMP = 0xffffffffffff

/**
 * Maximum value for a 2-byte unsigned integer.
 * Upper bound for the resolved nodeId and sequence fields.
 */
const MAX_UINT16 = 0xffff // 65535

/**
 * Maximum value for a 1-byte unsigned integer.
 * Upper bound for the keyVersion field.
 */
const MAX_UINT8 = 0xff // 255

/**
 * Number of bytes in the HMAC-SHA256 signature appended to each ID.
 * Truncated from 32 bytes to 7 bytes (56 bits) for compactness.
 *
 * Security note:
 *   56 bits = ~72 quadrillion possible values. Sufficient against random forgery.
 *   Pair with API-level rate limiting to prevent targeted brute-force.
 */
const SIGNATURE_BYTES = 7

/**
 * Byte count of the unsigned payload (all fields before the signature).
 * [keyVersion: 1B][timestamp: 6B][nodeId: 2B][sequence: 2B] = 11 bytes
 */
const PAYLOAD_BYTES = 11

/**
 * Total binary size of a VID. Always exactly 18 bytes regardless of
 * whether nodeId was provided as a number or string.
 */
export const VID_TOTAL_BYTES = PAYLOAD_BYTES + SIGNATURE_BYTES // 18

/**
 * Maximum IDs per node per millisecond before the generator blocks
 * and waits for the next clock tick. (2 bytes = values 0–65535)
 */
const MAX_SEQUENCE = MAX_UINT16

/**
 * Maximum milliseconds to spin-wait for the clock to advance when
 * sequence space is exhausted. Guards against frozen/broken clocks.
 */
const MAX_CLOCK_WAIT_MS = 5_000


export interface VIDGeneratorConfig {
  secret: Uint8Array
  keyVersion: number
  /**
   * Unique identifier for this generator instance.
   *
   * Accepts:
   *   - number → used directly. Must be an integer in range 0–65535.
   *   - string → SHA-256 hashed to a stable uint16 (0–65535).
   *              Deterministic: the same string always produces the same uint16
   *              across restarts. Useful for pod names, hostnames, container IDs.
   *
   * Examples:
   *   nodeId: 42
   *   nodeId: "pod-backend-7d9f"
   *   nodeId: "worker-us-east-1a"
   *
   * The binary layout is always 18 bytes regardless of input type —
   * strings are hashed internally before encoding.
   *
   * Must be unique across all concurrently running instances.
   * Shared nodeIds allow timestamp + sequence collisions.
   *
   * String collision note:
   *   Two different strings can resolve to the same uint16 (~1-in-65536 per pair).
   *   At small node counts this is negligible. At 100s of distinct nodes,
   *   prefer numeric nodeIds or a coordination registry.
   */
  nodeId: number | string
}


export interface NodeIdResolution {
  /** Resolved uint16 value written into the binary payload. */
  nodeId: number
  /** Where the value came from — useful for startup diagnostics. */
  source: "explicit_number" | "explicit_string" | "pod_ip" | "hostname" | "random"
  /** Set when source is "random" — caller should log this prominently. */
  warning?: string
}

/**
 * Resolves a 2-byte nodeId (0–65535) from config or environment in priority order:
 *
 *   1. Explicit numeric config  — user-managed, no hashing
 *   2. Explicit string config   — hashed to uint16, deterministic
 *   3. POD_IP env var           — unique per pod in Kubernetes (Downward API)
 *   4. HOSTNAME env var         — unique per container in Docker / ECS
 *   5. Random fallback          — warns loudly; safe only for single-instance use
 *
 * Kubernetes setup for automatic POD_IP injection:
 *   env:
 *     - name: POD_IP
 *       valueFrom:
 *         fieldRef:
 *           fieldPath: status.podIP
 */
export class NodeIdResolver {
  /**
   * Resolves the best available nodeId and returns metadata about its origin.
   *
   * @param explicitNodeId - Optional value from VID.initialize() config.
   * @returns NodeIdResolution containing the resolved nodeId and its source.
   *
   * @throws {RangeError} If explicit numeric nodeId is outside 0–65535.
   * @throws {TypeError}  If explicit string nodeId is empty.
   */
  static resolve(explicitNodeId?: number | string): NodeIdResolution {
    // 1. Explicit numeric — user takes full responsibility for uniqueness
    if (typeof explicitNodeId === "number") {
      if (!Number.isInteger(explicitNodeId) || explicitNodeId < 0 || explicitNodeId > MAX_UINT16) {
        throw new RangeError(
          `VID: explicit nodeId must be an integer between 0 and ${MAX_UINT16}. ` +
          `Received: ${explicitNodeId}`
        )
      }
      return { nodeId: explicitNodeId, source: "explicit_number" }
    }

    // 2. Explicit string — hashed to uint16 for fixed binary layout
    if (typeof explicitNodeId === "string") {
      if (explicitNodeId.trim().length === 0) {
        throw new TypeError(
          `VID: nodeId string must not be empty. ` +
          `Provide a non-empty string or a numeric value 0–${MAX_UINT16}.`
        )
      }
      return {
        nodeId: NodeIdResolver.hashToUint16(explicitNodeId.trim()),
        source: "explicit_string",
      }
    }

    // 3. Kubernetes: POD_IP injected per pod via Downward API
    const podIp = process.env.POD_IP
    if (podIp && podIp.trim().length > 0) {
      return { nodeId: NodeIdResolver.hashToUint16(podIp.trim()), source: "pod_ip" }
    }

    // 4. Docker / ECS / bare-metal: HOSTNAME is unique per container by default
    const hostname = process.env.HOSTNAME
    if (hostname && hostname.trim().length > 0) {
      return { nodeId: NodeIdResolver.hashToUint16(hostname.trim()), source: "hostname" }
    }

    // 5. Random fallback
    //    Collision probability: P ≈ 1 - e^(-n²/131072)  (n = running instances)
    //    n=10 → ~0.07%  |  n=100 → ~3.6%  |  n=500 → ~85%
    const randomNodeId = crypto.randomInt(0, MAX_UINT16 + 1)
    return {
      nodeId: randomNodeId,
      source: "random",
      warning:
        `[VID] WARNING: nodeId randomly assigned (nodeId=${randomNodeId}). ` +
        `Safe for single-instance use only. In distributed deployments this risks ` +
        `ID collision. Fix: inject POD_IP (Kubernetes), use HOSTNAME (Docker), ` +
        `or pass nodeId explicitly: VID.initialize({ nodeId: 42 }) or ({ nodeId: "pod-name" }).`,
    }
  }

  /**
   * Hashes an arbitrary string to a stable uint16 (0–65535).
   * Uses SHA-256, reads the first 2 bytes as a big-endian unsigned integer.
   *
   * @param input - Non-empty, already-trimmed string.
   * @returns Deterministic uint16 in 0–65535.
   */
  static hashToUint16(input: string): number {
    const hash = crypto.createHash("sha256").update(input, "utf8").digest()
    return (hash[0] << 8) | hash[1]
  }
}

/**
 * Core ID generator for the VID system.
 *
 * Binary layout (18 bytes total, always fixed):
 *
 *   ┌────────────┬───────────┬────────┬──────────┬───────────┐
 *   │ KeyVersion │ Timestamp │ NodeId │ Sequence │ Signature │
 *   │   1 byte   │  6 bytes  │ 2 bytes│  2 bytes │  7 bytes  │
 *   └────────────┴───────────┴────────┴──────────┴───────────┘
 *
 * nodeId accepts string | number:
 *   number → written directly as uint16 (must be 0–65535)
 *   string → SHA-256 hashed to a stable uint16 before encoding
 *   Either way, the binary layout is always exactly 18 bytes.
 *
 * Uniqueness guarantee:
 *   Within a node  → timestamp + sequence (65,536 unique IDs/ms; blocks on overflow)
 *   Across nodes   → nodeId (holds as long as no two instances share a resolved nodeId)
 *
 * Security guarantee:
 *   7-byte HMAC-SHA256 over all payload bytes. Any modification invalidates
 *   the signature. Verified with constant-time comparison (no timing leaks).
 *
 * Thread safety:
 *   NOT safe across Node.js Worker threads — instantiate one per Worker.
 *   Safe within a single event loop (single-threaded, no concurrent mutation).
 *
 */
export class VIDGenerator {
  /** Millisecond timestamp of the most recently generated ID. */
  private lastTimestamp: number = 0

  /** Sequence counter within the current millisecond. Resets each new ms. */
  private sequence: number = 0

  /**
   * Resolves `nodeId: number | string` to a uint16 for the 2-byte binary field.
   *
   * number path: range-validated (0–65535), returned as-is.
   * string path: must be non-empty; hashed via NodeIdResolver.hashToUint16().
   *              The same string always produces the same uint16 across restarts.
   *
   * Both paths produce a uint16. The binary layout is always 18 bytes.
   *
   * @throws {TypeError}  Empty string nodeId or unsupported type.
   * @throws {RangeError} Numeric nodeId outside 0–65535.
   */
  private resolveNodeId(nodeId: number | string): number {
    if (typeof nodeId === "string") {
      if (nodeId.trim().length === 0) {
        throw new TypeError(
          `VID: nodeId string must not be empty. ` +
          `Provide a non-empty string (e.g. "pod-backend-7d9f") ` +
          `or a numeric value 0–${MAX_UINT16}.`
        )
      }
      // Delegates to NodeIdResolver for consistent hashing across the library
      return NodeIdResolver.hashToUint16(nodeId.trim())
    }

    if (typeof nodeId === "number") {
      if (!Number.isInteger(nodeId) || nodeId < 0 || nodeId > MAX_UINT16) {
        throw new RangeError(
          `VID: nodeId must be an integer between 0 and ${MAX_UINT16}. ` +
          `Received: ${nodeId}`
        )
      }
      return nodeId
    }

    // Unreachable in TypeScript — guard for plain JS callers
    throw new TypeError(
      `VID: nodeId must be a number (0–${MAX_UINT16}) or a non-empty string. ` +
      `Received type: ${typeof nodeId}`
    )
  }

  // ─── Validation ───────────────────────────────────────────────────────────

  /**
   * Validates keyVersion and secret before any state mutation.
   * nodeId validation is handled inside resolveNodeId().
   *
   * @throws {RangeError} keyVersion out of 0–255, or secret shorter than 32 bytes.
   * @throws {TypeError}  secret is not a Uint8Array.
   */
  private validateConfig(config: VIDGeneratorConfig): void {
    if (
      !Number.isInteger(config.keyVersion) ||
      config.keyVersion < 0 ||
      config.keyVersion > MAX_UINT8
    ) {
      throw new RangeError(
        `VID: keyVersion must be an integer between 0 and ${MAX_UINT8}. ` +
        `Received: ${config.keyVersion}`
      )
    }

    if (!(config.secret instanceof Uint8Array) || config.secret.length === 0) {
      throw new TypeError(
        `VID: secret must be a non-empty Uint8Array. ` +
        `Ensure VID.initialize() was called with a valid secret string.`
      )
    }

    if (config.secret.length < 32) {
      throw new RangeError(
        `VID: secret must be at least 32 bytes (256 bits) for HMAC-SHA256 security. ` +
        `Received ${config.secret.length} bytes. ` +
        `Derive via SHA-256 from a strong passphrase or generate 32 random bytes.`
      )
    }
  }


  /**
   * Returns the next monotonic { timestamp, sequence } pair:
   *   - Freezes at lastTimestamp on clock drift (NTP sync, VM migration)
   *   - Increments sequence within the same millisecond
   *   - Blocks (spin-waits) when sequence overflows, rather than wrapping silently
   *
   * @throws {Error} Clock frozen beyond MAX_CLOCK_WAIT_MS.
   */
  private nextTimestampAndSequence(): { timestamp: number; sequence: number } {
    let timestamp = TimeUtils.now()

    // Clock drift: freeze at lastTimestamp to preserve monotonicity.
    if (timestamp < this.lastTimestamp) {
      timestamp = this.lastTimestamp
    }

    if (timestamp === this.lastTimestamp) {
      this.sequence++

      if (this.sequence > MAX_SEQUENCE) {
        // Sequence exhausted — block until clock advances.
        timestamp = this.waitForNextMillisecond(this.lastTimestamp)
        this.sequence = 0
      }
    } else {
      this.sequence = 0
    }

    this.lastTimestamp = timestamp
    return { timestamp, sequence: this.sequence }
  }

  /**
   * Spin-waits until the clock advances past sinceTimestamp.
   * Bounded by MAX_CLOCK_WAIT_MS to prevent infinite loops on broken clocks.
   *
   * @throws {Error} If the clock does not advance within MAX_CLOCK_WAIT_MS.
   */
  private waitForNextMillisecond(sinceTimestamp: number): number {
    const deadline = Date.now() + MAX_CLOCK_WAIT_MS
    let now: number

    do {
      now = TimeUtils.now()

      if (Date.now() > deadline) {
        throw new Error(
          `VID: Clock appears frozen or severely regressed. ` +
          `Waited ${MAX_CLOCK_WAIT_MS}ms for timestamp to advance past ${sinceTimestamp}. ` +
          `Check system clock integrity (NTP sync, container time, VM migration).`
        )
      }
    } while (now <= sinceTimestamp)

    return now
  }

  /**
   * Encodes the 11-byte unsigned payload in big-endian byte order.
   * @param keyVersion - Validated key version (0–255).
   * @param timestamp  - Current ms timestamp (0–MAX_TIMESTAMP).
   * @param nodeId     - Already-resolved uint16 (0–65535). Never a string here.
   * @param sequence   - Sequence counter for this ms (0–65535).
   */
  private encodePayload(
    keyVersion: number,
    timestamp: number,
    nodeId: number,  
    sequence: number
  ): Uint8Array {
    const payload = new Uint8Array(PAYLOAD_BYTES)
    const view = new DataView(payload.buffer)

    view.setUint8(0, keyVersion)
    view.setUint32(1, Math.floor(timestamp / 0x10000))
    view.setUint16(5, timestamp % 0x10000)
    view.setUint16(7, nodeId)
    view.setUint16(9, sequence)

    return payload
  }

  /**
   * Generates a new VID.
   *
   * Properties of the returned identifier:
   *   - Globally unique (assuming unique resolved nodeId per running instance)
   *   - Time-sortable (binary sort order matches chronological order)
   *   - Cryptographically signed (7-byte HMAC-SHA256; tamper-evident)
   *   - Fixed 18 bytes in binary form — always, regardless of nodeId input type
   *   - 26 characters in base32 string form
   *
   * nodeId can be a number or a string:
   *   generate({ ..., nodeId: 42 })               // numeric, used directly
   *   generate({ ..., nodeId: "pod-backend-3" })  // string, hashed to uint16
   *
   * Throughput: up to 65,536 unique IDs/ms/node.
   * On overflow: spin-waits for the next ms tick (bounded; never wraps silently).
   *
   * @param config - { secret, keyVersion, nodeId }
   * @returns VIDValue wrapping the 18-byte binary identifier.
   *
   * @throws {RangeError} keyVersion out of 0–255; numeric nodeId out of 0–65535;
   *                      secret shorter than 32 bytes.
   * @throws {TypeError}  secret not a Uint8Array; nodeId is empty string or wrong type.
   * @throws {Error}      Timestamp overflow (year 10895+ CE); clock frozen > 5s;
   *                      internal HMACSigner length mismatch (library bug).
   */
  generate(config: VIDGeneratorConfig): VIDValue {
    // Validate config fields — fail fast before any state mutation
    this.validateConfig(config)

    // Resolve nodeId: string → hashed uint16, number → range-checked uint16
    // After this point, nodeId is always a plain number ready for encoding.
    const resolvedNodeId = this.resolveNodeId(config.nodeId)

    // 3. Advance clock/sequence
    const { timestamp, sequence } = this.nextTimestampAndSequence()

    // 4. Timestamp overflow guard (48-bit max; unreachable before year 10895 CE)
    if (timestamp > MAX_TIMESTAMP) {
      throw new Error(
        `VID: Timestamp overflow. Value (${timestamp}) exceeds 48-bit max (${MAX_TIMESTAMP}). ` +
        `Should not occur before year 10895 CE.`
      )
    }

    // 5. Encode 11-byte payload (keyVersion + timestamp + resolvedNodeId + sequence)
    const payload = this.encodePayload(config.keyVersion, timestamp, resolvedNodeId, sequence)

    // 6. HMAC-SHA256 over payload → truncate to SIGNATURE_BYTES
    const signature = HMACSigner.sign(payload, config.secret)

    if (signature.length !== SIGNATURE_BYTES) {
      throw new Error(
        `VID: Internal error — HMACSigner returned ${signature.length} bytes ` +
        `but ${SIGNATURE_BYTES} were expected. This is a bug in HMACSigner.sign().`
      )
    }

    // 7. payload (11B) + signature (7B) = 18-byte VID
    const binary = ByteUtils.concat(payload, signature)

    return new VIDValue(binary)
  }
}