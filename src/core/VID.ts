import { createHash } from "crypto"
import { VIDGenerator } from "./VIDGenerator"
import { VIDVerifier, VerifyResult } from "./VIDVerifier"
import { VIDParser } from "./VIDParser"
import { VIDValue } from "./VIDValue"
import { NodeIdResolver } from "./VIDGenerator"

/**
 * Minimum byte length of a derived secret key.
 */
const MIN_SECRET_CHARS = 16

/**
 * Maximum valid value for a 1-byte keyVersion field.
 * Supports up to 256 distinct key versions (0–255) for rotation.
 */
const MAX_KEY_VERSION = 255

/**
 * Maximum valid value for the 2-byte nodeId field.
 */
const MAX_NODE_ID = 65535


/**
 * Input shape for VID.initialize().
 *
 * keys:
 *   A record mapping keyVersion (as a number key) to a raw secret string.
 *   Multiple entries allow verifying IDs from previous key versions while
 *   generating new IDs with the current key.
 *
 *   Example with rotation:
 *     keys: {
 *       1: process.env.VID_SECRET_V1!,  // retained for verifying old IDs
 *       2: process.env.VID_SECRET_V2!,  // current — new IDs use this
 *     }
 *
 * currentKeyVersion:
 *   The keyVersion used when generating new IDs.
 *   Must exist as a key in the `keys` record above.
 *
 * nodeId (optional):
 *   Unique identifier for this instance. Accepts number (0–65535) or string
 *   (hashed to a stable uint16). If omitted, auto-detected from environment
 *   in priority order: POD_IP → HOSTNAME → random (with warning).
 *
 * See also: NodeIdResolver for auto-detection details.
 */
export interface VIDInitOptions {
  keys: Record<number, string>
  currentKeyVersion: number
  nodeId?: number | string
}

/**
 * Options for parse().
 */
export interface ParseOptions {
  /**
   * Whether to verify the HMAC signature before parsing.
   * Defaults to true. Set to false only when you have already verified
   * the VID earlier in the same request pipeline.
   *
   */
  verify?: boolean
}


/**
 * VID — Verifiable Identifier Engine.
 *
 * The single public entry point for generating, verifying, and parsing VIDs.
 * Create one instance per application (or per key-set) and reuse it.
 *
 * Responsibilities:
 *   - Derives and stores HMAC-SHA256 keys from raw secret strings
 *   - Resolves and locks in a nodeId at initialization time
 *   - Delegates to VIDGenerator, VIDVerifier, and VIDParser
 *   - Enforces verify-before-parse by default
 *
 * Usage:
 * const vid = VID.initialize({
 *   keys: { 1: process.env.VID_SECRET! },
 *   currentKeyVersion: 1,
 *   nodeId: "pod-backend-7d9f",  // or omit for auto-detection
 * })
 *
 * const id    = vid.generate()
 * const valid = vid.verify(id)
 * const meta  = vid.parse(id)
 */
export class VID {
  private readonly keys: Map<number, Uint8Array>
  private readonly currentKeyVersion: number
  private readonly nodeId: number
  private readonly generator: VIDGenerator

  private constructor(options: VIDInitOptions) {
    VID.validateOptions(options)

    this.keys = new Map<number, Uint8Array>()

    for (const [versionKey, rawSecret] of Object.entries(options.keys)) {
      const version = Number(versionKey)
      const derived = VID.deriveKey(rawSecret)
      this.keys.set(version, derived)
    }

    this.currentKeyVersion = options.currentKeyVersion

    const resolution = NodeIdResolver.resolve(options.nodeId)

    if (resolution.warning) {
      console.warn(resolution.warning)
    }

    this.nodeId = resolution.nodeId
    this.generator = new VIDGenerator()
  }

  /**
   * Creates and returns a configured VID engine instance.
   *
   * Call once at application startup and store the result.
   * Do not call on every request — the generator holds sequence state.
   *
   * @param options - Keys, currentKeyVersion, and optional nodeId.
   * @returns Configured VID instance ready to generate, verify, and parse.
   *
   * @throws {TypeError}  Missing or wrong-typed options fields.
   * @throws {RangeError} keyVersion out of 0–255; nodeId number out of 0–65535;
   *                      secret string shorter than MIN_SECRET_CHARS.
   * @throws {Error}      currentKeyVersion not present in the keys record.
   *
   * @example
   * ```ts
   * const vid = VID.initialize({
   *   keys: { 1: process.env.VID_SECRET! },
   *   currentKeyVersion: 1,
   * })
   * ```
   */
  static initialize(options: VIDInitOptions): VID {
    return new VID(options)
  }

  /**
   * Generates a new VID using the current key version and resolved nodeId.
   *
   * The returned VIDValue is:
   *   - Globally unique (assuming unique nodeId per running instance)
   *   - Time-sortable (binary sort matches chronological order)
   *   - HMAC-signed (7-byte SHA-256 truncation; tamper-evident)
   *   - Exactly 18 bytes binary / 26 characters base32
   *
   * Throughput: up to 65,536 unique IDs/ms on this instance.
   * Overflow: generator blocks (spin-waits) until next ms — never wraps silently.
   *
   * This method is synchronous.
   *
   * @returns VIDValue wrapping the 18-byte binary identifier.
   *
   * @throws {Error} On clock freeze beyond 5s or timestamp overflow (year 10895+).
   *
   * @example
   * ```ts
   * const id = vid.generate()
   * console.log(id.toString())  // "AEAZY4DVF7PQAKQAAA2PMOJS2DIBB"
   * console.log(id.toBinary())  // Uint8Array(18)
   * ```
   */
  generate(): VIDValue {
    const secret = this.keys.get(this.currentKeyVersion)!

    return this.generator.generate({
      secret,
      keyVersion: this.currentKeyVersion,
      nodeId: this.nodeId,
    })
  }

  /**
   * Verifies a VID's HMAC signature and returns a plain boolean.
   *
   * Uses the keyVersion embedded in the VID to select the correct key,
   * so IDs from previous key versions verify correctly as long as their
   * key is still in the keys map.
   *
   * All invalid inputs (wrong type, wrong length, bad characters) return
   * false — never throw. This makes middleware simple and safe:
   *   if (!vid.verify(input)) return res.status(400).send()
   *
   * Accepts all VID representations:
   *   string | Uint8Array | Buffer | ArrayBuffer | VIDValue
   *
   * @param input - VID in any accepted representation.
   * @returns true if authentic; false for any invalid or forged input.
   *
   * @example
   * ```ts
   * vid.verify("AEAZY4DVF7PQAKQAAA2PMOJS2DIBB")  // string
   * vid.verify(id.toBinary())                    // Uint8Array
   * vid.verify(id)                               // VIDValue
   * ```
   */
  verify(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue
  ): boolean {
    return VIDVerifier.verify(input, this.keys)
  }

  /**
   * Verifies a VID and returns a typed result with a failure reason.
   *
   * Use this in middleware or audit logging where you need to understand
   * and record why a verification failed.
   *
   * ⚠️  Never expose the failure reason to external API clients.
   *     Log it internally; return a generic error to the client.
   *
   * @param input - VID in any accepted representation.
   * @returns VerifyResult — { valid: true } or { valid: false, reason: ... }
   *
   * @example
   * ```ts
   * const result = vid.verifyDetailed(input)
   * if (!result.valid) {
   *   logger.warn("VID failed", { reason: result.reason, path: req.path })
   *   return res.status(400).json({ error: "Invalid ID" })
   * }
   * ```
   */
  verifyDetailed(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue
  ): VerifyResult {
    return VIDVerifier.verifyDetailed(input, this.keys)
  }

  /**
   * Parses a VID into its structured metadata.
   *
   * By default, HMAC signature verification is performed before parsing.
   * This is the safe default — always verify before trusting metadata.
   *
   * Set { verify: false } only when you have already verified the VID
   * earlier in the same request pipeline and want to avoid a second HMAC
   * computation on the hot path.
   *
   * @param input   - VID in any accepted representation.
   * @param options - { verify?: boolean } (default: true)
   * @returns Frozen VIDMetadata with keyVersion, timestamp, date, iso, nodeId, sequence.
   *
   * @throws {Error}      If verification is enabled and the VID is invalid.
   * @throws {RangeError} If the binary is structurally invalid (wrong length, bad timestamp).
   *
   * @example
   * ```ts
   * // Standard — verify + parse in one call
   * const meta = vid.parse(id)
   *
   * // Skip verify if already verified upstream
   * const meta = vid.parse(id, { verify: false })
   *
   * console.log(meta.iso)       // "2026-02-18T10:12:34.567Z"
   * console.log(meta.nodeId)    // 42
   * console.log(meta.sequence)  // 7
   * ```
   */
  parse(
    input: string | Uint8Array | Buffer | ArrayBuffer | VIDValue,
    options?: ParseOptions
  ): ReturnType<typeof VIDParser.parse> {
    const shouldVerify = options?.verify !== false

    if (shouldVerify) {
      const result = VIDVerifier.verifyDetailed(input, this.keys)

      if (!result.valid) {
        // Use verifyDetailed internally so the specific reason is available
        // for the error message — but do NOT leak it to the caller's catch block
        // as a structured property. The caller gets a clear message; the reason
        // stays in our logs via the caller's error handler if they choose to log it.
        throw new Error(
          `VID.parse: verification failed before parsing. ` +
          `Reason: ${result.reason}. ` +
          `Ensure the VID was generated by a trusted source with the correct secret.`
        )
      }
    }

    return VIDParser.parse(input)
  }

  // ─── Diagnostics ─────────────────────────────────────────────────────────

  /**
   * Returns the resolved nodeId embedded in every ID generated by this instance.
   *
   * Useful for startup logging and debugging nodeId collision issues.
   * The returned value is always a uint16 (0–65535) regardless of whether
   * nodeId was configured as a number or string.
   *
   * @example
   * ```ts
   * logger.info("VID engine initialized", {
   *   nodeId: vid.getNodeId(),
   *   keyVersion: vid.getCurrentKeyVersion(),
   * })
   * ```
   */
  getNodeId(): number {
    return this.nodeId
  }

  /**
   * Returns the keyVersion currently used for generating new IDs.
   * Useful for startup logging and confirming key rotation took effect.
   */
  getCurrentKeyVersion(): number {
    return this.currentKeyVersion
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────

  /**
   * Derives a 32-byte HMAC key from a raw secret string via SHA-256.
   *
   * The raw secret string is encoded as UTF-8 before hashing.
   * Output is always exactly 32 bytes — the optimal key length for HMAC-SHA256.
   *
   * The raw string is never stored. If the derived key is accidentally logged,
   * it cannot be reversed to recover the original secret.
   *
   * @param rawSecret - Raw secret string from configuration. Already validated.
   * @returns 32-byte derived key as Uint8Array.
   */
  private static deriveKey(rawSecret: string): Uint8Array {
    return new Uint8Array(
      createHash("sha256")
        .update(rawSecret, "utf8")
        .digest()
    )
  }

  /**
   * Validates all options fields at initialization time.
   * Throws descriptive errors before any state is mutated.
   *
   * Separated from the constructor so all validation is in one place
   * and can be read/tested independently.
   *
   * @throws {TypeError}  Missing or wrong-typed fields.
   * @throws {RangeError} Out-of-range numeric fields or short secrets.
   * @throws {Error}      currentKeyVersion not found in keys record.
   */
  private static validateOptions(options: VIDInitOptions): void {
    if (options === null || options === undefined) {
      throw new TypeError(
        `VID.initialize: options is required. ` +
        `Received: ${options === null ? "null" : "undefined"}`
      )
    }

    if (typeof options !== "object" || Array.isArray(options)) {
      throw new TypeError(
        `VID.initialize: options must be a plain object. Received: ${typeof options}`
      )
    }

    // ── keys ──────────────────────────────────────────────────────────────
    if (options.keys === null || options.keys === undefined) {
      throw new TypeError(
        `VID.initialize: options.keys is required. ` +
        `Expected: Record<number, string> e.g. { 1: process.env.VID_SECRET! }`
      )
    }

    if (typeof options.keys !== "object" || Array.isArray(options.keys)) {
      throw new TypeError(
        `VID.initialize: options.keys must be a plain object (Record<number, string>). ` +
        `Received: ${typeof options.keys}`
      )
    }

    const entries = Object.entries(options.keys)

    if (entries.length === 0) {
      throw new RangeError(
        `VID.initialize: options.keys must contain at least one entry. ` +
        `Example: { 1: process.env.VID_SECRET! }`
      )
    }

    for (const [versionStr, secret] of entries) {
      const version = Number(versionStr)

      if (!Number.isInteger(version) || version < 0 || version > MAX_KEY_VERSION) {
        throw new RangeError(
          `VID.initialize: key version must be an integer between 0 and ${MAX_KEY_VERSION}. ` +
          `Received: "${versionStr}"`
        )
      }

      if (typeof secret !== "string") {
        throw new TypeError(
          `VID.initialize: secret for keyVersion ${version} must be a string. ` +
          `Received: ${typeof secret}`
        )
      }

      // Validate byte length of the UTF-8 encoded secret, not just char count.
      // A string with 16 emoji characters has 16 chars but 64+ UTF-8 bytes —
      // both pass this check. A string with 16 ASCII chars has 16 bytes — also passes.
      // The important thing is rejecting "abc" or other obviously weak inputs.
      const secretByteLength = new TextEncoder().encode(secret).length

      if (secretByteLength < MIN_SECRET_CHARS) {
        throw new RangeError(
          `VID.initialize: secret for keyVersion ${version} must be at least ` +
          `${MIN_SECRET_CHARS} characters. ` +
          `Received ${secret.length} characters (${secretByteLength} UTF-8 bytes). ` +
          `Use a strong randomly-generated secret: crypto.randomBytes(32).toString('hex')`
        )
      }
    }

    // ── currentKeyVersion ─────────────────────────────────────────────────
    if (!Number.isInteger(options.currentKeyVersion)) {
      throw new TypeError(
        `VID.initialize: currentKeyVersion must be an integer. ` +
        `Received: ${typeof options.currentKeyVersion} (${options.currentKeyVersion})`
      )
    }

    if (options.currentKeyVersion < 0 || options.currentKeyVersion > MAX_KEY_VERSION) {
      throw new RangeError(
        `VID.initialize: currentKeyVersion must be between 0 and ${MAX_KEY_VERSION}. ` +
        `Received: ${options.currentKeyVersion}`
      )
    }

    // currentKeyVersion must exist in keys — you cannot generate IDs with a
    // key you haven't provided. This catches the common mistake of rotating
    // currentKeyVersion without adding the new key to the keys record.
    if (!(String(options.currentKeyVersion) in options.keys) &&
        !(options.currentKeyVersion in options.keys)) {
      throw new Error(
        `VID.initialize: currentKeyVersion ${options.currentKeyVersion} is not present ` +
        `in options.keys. Add it: keys: { ${options.currentKeyVersion}: process.env.VID_SECRET! }`
      )
    }

    // ── nodeId (optional) ─────────────────────────────────────────────────
    // Type and range validation for numeric nodeId.
    // String nodeId is validated inside NodeIdResolver.resolve().
    if (options.nodeId !== undefined && typeof options.nodeId === "number") {
      if (!Number.isInteger(options.nodeId) || options.nodeId < 0 || options.nodeId > MAX_NODE_ID) {
        throw new RangeError(
          `VID.initialize: nodeId must be an integer between 0 and ${MAX_NODE_ID}. ` +
          `Received: ${options.nodeId}`
        )
      }
    }
  }
}