/**
 * Low-level byte manipulation utilities for VID binary operations.
 */
export class ByteUtils {
  /**
   * Concatenates two Uint8Arrays into a single fresh Uint8Array.
   * 
   * @param a - First Uint8Array (or Buffer). May be a subarray view.
   * @param b - Second Uint8Array (or Buffer). May be a subarray view.
   * @returns A new Uint8Array of length a.length + b.length containing
   *          the bytes of a followed by the bytes of b.
   *
   * @throws {TypeError} If either argument is not a Uint8Array (or Buffer).
   */
  static concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    ByteUtils.assertUint8Array(a, "a")
    ByteUtils.assertUint8Array(b, "b")

    const out = new Uint8Array(a.length + b.length)

    // set() copies bytes from the source's byteOffset for source.length bytes.
    // This correctly handles subarray views — it does NOT read from position 0
    // of the backing ArrayBuffer, only from the view's own byte range.
    out.set(a, 0)
    out.set(b, a.length)

    return out
  }

  /**
   * Performs a non-constant-time byte-for-byte equality check.
   *
   * Returns true if and only if both arrays have identical length and
   * identical bytes at every position. Comparison exits early on first
   * mismatch — this is NOT suitable for comparing secrets or signatures
   * (use crypto.timingSafeEqual for that; see HMACSigner.verify()).
   *
   * Use cases: deduplication checks, cache key comparison, test assertions.
   *
   * @param a - First Uint8Array. May be a subarray view.
   * @param b - Second Uint8Array. May be a subarray view.
   * @returns true if both arrays contain identical bytes; false otherwise.
   *
   * @throws {TypeError} If either argument is not a Uint8Array (or Buffer).
   */
  static equal(a: Uint8Array, b: Uint8Array): boolean {
    ByteUtils.assertUint8Array(a, "a")
    ByteUtils.assertUint8Array(b, "b")

    if (a.length !== b.length) {
      return false
    }

    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        return false
      }
    }

    return true
  }

  /**
   * Returns a fresh, independent copy of the given Uint8Array.
   *
   * Use when you need to retain bytes from a view that may be invalidated
   * or mutated, or to break the reference to a shared/pooled buffer.
   *
   * This is equivalent to `new Uint8Array(src)` for non-view arrays, but
   * correctly handles subarray views by copying only the intended byte range.
   *
   * @param src - Source Uint8Array. May be a subarray view or Buffer.
   * @returns A new Uint8Array with the same length and byte values as src.
   *
   * @throws {TypeError} If src is not a Uint8Array (or Buffer).
   */
  static copy(src: Uint8Array): Uint8Array {
    ByteUtils.assertUint8Array(src, "src")

    const out = new Uint8Array(src.length)
    out.set(src, 0)
    return out
  }

  /**
   * Asserts that a value is a Uint8Array (or Buffer, which extends Uint8Array).
   *
   * Throws a TypeError with the parameter name and received type if the
   * assertion fails. Using a dedicated helper keeps error messages consistent
   * and avoids repeating the same guard across every public method.
   *
   * @param value     - Value to check.
   * @param paramName - Name of the parameter, for the error message.
   *
   * @throws {TypeError} If value is not a Uint8Array.
   */
  
  private static assertUint8Array(value: unknown, paramName: string): void {
    if (!(value instanceof Uint8Array)) {
      throw new TypeError(
        `ByteUtils: "${paramName}" must be a Uint8Array or Buffer. ` +
        `Received: ${value === null ? "null" : value === undefined ? "undefined" : typeof value}`
      )
    }
  }
}