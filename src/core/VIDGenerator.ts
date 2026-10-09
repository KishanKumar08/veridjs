import * as crypto from "crypto"
import { threadId } from "worker_threads"
import { HMACSigner } from "../crypto/HMACSigner"
import { VIDValue } from "./VIDValue"
import { TimeUtils } from "../utils/TimeUtils"

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
 * Highest sequence value before the generator blocks for the next millisecond.
 */
const MAX_SEQUENCE = MAX_UINT16

/**
 * Each millisecond's sequence starts at a random value in [0, SEQUENCE_START_MASK].
 *
 * If two generators ever end up with the same nodeId, IDs collide only when
 * they also pick the same starting sequence in the same millisecond — a
 * 1-in-32,768 event instead of a certainty. It still leaves at least 32,768
 * IDs per millisecond per node (≈ 32 million per second).
 */
const SEQUENCE_START_MASK = 0x7fff

/**
 * Maximum milliseconds to spin-wait for the clock to advance when
 * sequence space is exhausted. Guards against frozen/broken clocks.
 */
const MAX_CLOCK_WAIT_MS = 5_000


export interface VIDGeneratorConfig {
  /** Raw secret (≥ 32 bytes) or a KeyObject from HMACSigner.createKey(). */
  secret: Uint8Array | crypto.KeyObject
  keyVersion: number
  /**
   * Unique identifier for this generator instance.
   *
   *   - number → used directly. Must be an integer in range 0–65535.
   *   - string → SHA-256 hashed to a stable uint16 (0–65535).
   *
   * Must be unique across all concurrently running instances; see
   * NodeIdResolver for the collision math.
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
 *   3. POD_IP env var           — Kubernetes (Downward API)
 *   4. HOSTNAME env var         — Docker / ECS / bare metal
 *   5. Random fallback          — warns; safe only for single-instance use
 *
 * Auto-detected values (3, 4) also mix in the process id and worker thread id,
 * so cluster mode, PM2, and worker_threads on one host get different nodeIds.
 *
 * Collisions: a uint16 has 65,536 values, so with n hashed or random nodeIds
 * the chance that any two share one is ≈ 1 − e^(−n²/131072):
 *   n=10 → 0.07%  |  n=100 → 7%  |  n=300 → 50%
 * Fleets of more than a few dozen instances should assign numeric nodeIds
 * (e.g. a StatefulSet ordinal). The randomized per-millisecond sequence start
 * makes a shared nodeId far less likely to produce a duplicate, but numeric
 * assignment is the only guarantee.
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
   * @throws {TypeError}  If explicit nodeId is an empty string or another type.
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

    if (explicitNodeId !== undefined) {
      throw new TypeError(
        `VID: nodeId must be a number (0–${MAX_UINT16}) or a non-empty string. ` +
        `Received type: ${typeof explicitNodeId}`
      )
    }

    // 3. Kubernetes: POD_IP injected per pod via Downward API
    const podIp = process.env.POD_IP?.trim()
    if (podIp) {
      return { nodeId: NodeIdResolver.hashToUint16(NodeIdResolver.perProcess(podIp)), source: "pod_ip" }
    }

    // 4. Docker / ECS / bare-metal: HOSTNAME is unique per container by default
    const hostname = process.env.HOSTNAME?.trim()
    if (hostname) {
      return { nodeId: NodeIdResolver.hashToUint16(NodeIdResolver.perProcess(hostname)), source: "hostname" }
    }

    // 5. Random fallback
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
   * Hashes a string to a uint16 using the first two bytes of its SHA-256.
   */
  static hashToUint16(input: string): number {
    const hash = crypto.createHash("sha256").update(input, "utf8").digest()
    return (hash[0] << 8) | hash[1]
  }

  /**
   * Scopes a host identity to this process and thread. Several processes on
   * one host (cluster mode, PM2) share a hostname; worker threads also share
   * a pid. Each runs its own generator, so each needs its own nodeId.
   */
  private static perProcess(hostIdentity: string): string {
    return `${hostIdentity}#${process.pid}#${threadId}`
  }
}

/**
 * Stateful, monotonic VID generator bound to one key, key version and nodeId.
 *
 * Config is validated once in the constructor, so generate() does only the
 * per-ID work: advance the clock/sequence, encode 11 bytes, sign them.
 *
 * Keep one instance per process — two generators with the same nodeId in
 * one process can emit the same timestamp + sequence.
 */
export class VIDGenerator {
  private readonly key: crypto.KeyObject
  private readonly keyVersion: number
  private readonly nodeId: number

  private lastTimestamp = 0
  private sequence = 0

  /** Pool of random uint16s for sequence starts, refilled in bulk. */
  private readonly randomPool = new Uint16Array(256)
  private randomIndex = this.randomPool.length

  /**
   * @throws {RangeError} keyVersion out of 0–255; numeric nodeId out of 0–65535;
   *                      secret shorter than 32 bytes.
   * @throws {TypeError}  secret not a Uint8Array/KeyObject; nodeId is empty string or wrong type.
   */
  constructor(config: VIDGeneratorConfig) {
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

    this.key = config.secret instanceof crypto.KeyObject
      ? config.secret
      : HMACSigner.createKey(config.secret)
    this.keyVersion = config.keyVersion
    this.nodeId = NodeIdResolver.resolve(config.nodeId).nodeId
  }

  /**
   * Generates a new VID.
   *
   * Properties of the returned identifier:
   *   - Unique (assuming a unique nodeId per running generator)
   *   - Time-sortable (binary sort order matches chronological order)
   *   - Cryptographically signed (7-byte HMAC-SHA256; tamper-evident)
   *   - 18 bytes binary / 29 characters base32
   *
   * Throughput: at least 32,768 IDs/ms/node.
   * On overflow: spin-waits for the next ms tick (bounded; never wraps silently).
   *
   * @throws {Error} Timestamp overflow (year 10895+ CE); clock frozen > 5s.
   */
  generate(): VIDValue {
    const { timestamp, sequence } = this.nextTimestampAndSequence()

    // 48-bit max; unreachable before year 10895 CE
    if (timestamp > MAX_TIMESTAMP) {
      throw new Error(
        `VID: Timestamp overflow. Value (${timestamp}) exceeds 48-bit max (${MAX_TIMESTAMP}). ` +
        `Should not occur before year 10895 CE.`
      )
    }

    // Encode the 11-byte payload big-endian, then sign it in place:
    // [keyVersion:1][timestamp:6][nodeId:2][sequence:2][signature:7]
    const binary = new Uint8Array(VID_TOTAL_BYTES)
    const view = new DataView(binary.buffer)

    view.setUint8(0, this.keyVersion)
    view.setUint32(1, Math.floor(timestamp / 0x10000))
    view.setUint16(5, timestamp % 0x10000)
    view.setUint16(7, this.nodeId)
    view.setUint16(9, sequence)

    HMACSigner.signInto(binary.subarray(0, PAYLOAD_BYTES), this.key, binary, PAYLOAD_BYTES)

    return new VIDValue(binary)
  }

  /** The resolved uint16 nodeId written into every ID. */
  getNodeId(): number {
    return this.nodeId
  }

  /**
   * Returns the next monotonic { timestamp, sequence } pair:
   *   - Freezes at lastTimestamp on clock drift (NTP sync, VM migration)
   *   - Starts each new millisecond at a random sequence in [0, 32767]
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
        this.sequence = this.randomSequenceStart()
      }
    } else {
      this.sequence = this.randomSequenceStart()
    }

    this.lastTimestamp = timestamp
    return { timestamp, sequence: this.sequence }
  }

  private randomSequenceStart(): number {
    if (this.randomIndex === this.randomPool.length) {
      crypto.randomFillSync(this.randomPool)
      this.randomIndex = 0
    }
    return this.randomPool[this.randomIndex++] & SEQUENCE_START_MASK
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
}
