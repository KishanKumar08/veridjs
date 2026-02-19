/**
 * Millisecond clock provider for VID timestamp generation.
*/
export class TimeUtils {
  private static _provider: (() => number) | undefined = undefined

  /**
   * Returns the current Unix timestamp in milliseconds.
   * 
   * The returned value must be:
   *   - A positive integer
   *   - Within the 48-bit timestamp range VID supports (~year 10895 CE)
   *   - Monotonically non-decreasing when called without a clock override
   *     (Date.now() can go backward on NTP sync; VIDGenerator handles that)
   *
   * @returns Current millisecond timestamp as a safe positive integer.
   */
  static now(): number {
    const ts = TimeUtils._provider !== undefined
      ? TimeUtils._provider()
      : Date.now()

    return ts
  }

}