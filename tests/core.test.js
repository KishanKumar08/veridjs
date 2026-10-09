// Behaviour of generate / verify / parse / VIDValue against the built package.
const { test, describe, afterEach } = require("node:test")
const assert = require("node:assert/strict")
const util = require("node:util")
const { Worker } = require("node:worker_threads")
const { VID, VIDValue } = require("@veridjs/core")
const { TimeUtils } = require("../dist/utils/TimeUtils.js")

const SECRET = "a-test-secret-of-at-least-sixteen-chars"
const OTHER_SECRET = "a-completely-different-secret-value"
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

const make = (extra = {}) =>
  VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: 7, ...extra })

afterEach(() => TimeUtils.setProvider(undefined))

describe("generate", () => {
  test("produces 18 bytes and a 29-character base32 string", () => {
    const id = make().generate()
    assert.equal(id.toBinary().length, 18)
    assert.match(id.toString(), /^[A-Z2-7]{29}$/)
  })

  test("100k IDs are unique and come out in binary sort order", () => {
    const vid = make()
    const ids = Array.from({ length: 100_000 }, () => vid.generate())
    assert.equal(new Set(ids.map(String)).size, ids.length)
    for (let i = 1; i < ids.length; i++) {
      assert.equal(VIDValue.compare(ids[i - 1], ids[i]), -1, `out of order at ${i}`)
    }
  })

  test("embeds key version, node id and the current time", () => {
    const before = Date.now()
    const meta = make({ nodeId: 4242 }).generate().parse()
    assert.equal(meta.keyVersion, 1)
    assert.equal(meta.nodeId, 4242)
    assert.ok(meta.timestamp >= before && meta.timestamp <= Date.now())
    assert.equal(meta.iso, new Date(meta.timestamp).toISOString())
  })

  test("stays monotonic when the clock goes backwards", () => {
    const vid = make()
    let now = 1_800_000_000_000
    TimeUtils.setProvider(() => now)
    const a = vid.generate()
    now -= 10_000
    const b = vid.generate()
    assert.equal(VIDValue.compare(a, b), -1)
    assert.equal(b.parse().timestamp, a.parse().timestamp)
    assert.equal(vid.verify(b), true)
  })

  test("waits for the next millisecond instead of wrapping the sequence", () => {
    const vid = make()
    const t = 1_800_000_000_000
    let calls = 0
    // The clock ticks once per 70k reads, so each millisecond's sequence
    // space (≤ 65,536) runs out and the generator has to wait for the tick.
    TimeUtils.setProvider(() => t + Math.floor(calls++ / 70_000))
    const ids = Array.from({ length: 150_000 }, () => vid.generate())
    assert.equal(new Set(ids.map(String)).size, ids.length)
    for (let i = 1; i < ids.length; i++) {
      assert.equal(VIDValue.compare(ids[i - 1], ids[i]), -1)
    }
    assert.ok(ids.at(-1).parse().timestamp >= t + 2)
  })

  test("each millisecond starts at a random sequence below 32768", () => {
    const vid = make()
    let now = 1_800_000_000_000
    TimeUtils.setProvider(() => now++)
    const starts = Array.from({ length: 200 }, () => vid.generate().parse().sequence)
    assert.ok(starts.every((s) => s >= 0 && s <= 0x7fff))
    assert.ok(new Set(starts).size > 150, "sequence starts should vary")
  })
})

describe("verify", () => {
  const vid = make()
  const id = vid.generate()
  const text = id.toString()

  test("accepts every representation", () => {
    const bin = id.toBinary()
    assert.equal(vid.verify(id), true)
    assert.equal(vid.verify(text), true)
    assert.equal(vid.verify(bin), true)
    assert.equal(vid.verify(Buffer.from(bin)), true)
    assert.equal(vid.verify(bin.buffer), true)
    assert.equal(vid.verify(text.toLowerCase()), true)
    assert.equal(vid.verify(`  ${text}\n`), true)
  })

  test("rejects every single-bit change to the binary", () => {
    const bin = id.toBinary()
    for (let byte = 0; byte < 18; byte++) {
      for (let bit = 0; bit < 8; bit++) {
        const tampered = new Uint8Array(bin)
        tampered[byte] ^= 1 << bit
        assert.equal(vid.verify(tampered), false, `byte ${byte} bit ${bit}`)
      }
    }
  })

  test("rejects every single-character change to the string", () => {
    for (let i = 0; i < text.length; i++) {
      for (const c of ALPHABET) {
        if (c === text[i]) continue
        const tampered = text.slice(0, i) + c + text.slice(i + 1)
        assert.equal(vid.verify(tampered), false, `position ${i} → ${c}`)
      }
    }
  })

  test("each ID has exactly one valid string form", () => {
    const last = ALPHABET.indexOf(text.at(-1))
    const twin = text.slice(0, -1) + ALPHABET[last ^ 1]
    assert.deepEqual(vid.verifyDetailed(twin), { valid: false, reason: "NON_CANONICAL_STRING" })
  })

  test("rejects IDs signed with a different secret", () => {
    const foreign = VID.initialize({ keys: { 1: OTHER_SECRET }, currentKeyVersion: 1, nodeId: 7 }).generate()
    assert.deepEqual(vid.verifyDetailed(foreign), { valid: false, reason: "SIGNATURE_MISMATCH" })
  })

  test("never throws, and names the reason", () => {
    const cases = [
      [null, "NULL_INPUT"],
      [undefined, "NULL_INPUT"],
      [42, "UNSUPPORTED_TYPE"],
      [{}, "UNSUPPORTED_TYPE"],
      [[], "UNSUPPORTED_TYPE"],
      [Symbol("x"), "UNSUPPORTED_TYPE"],
      [10n, "UNSUPPORTED_TYPE"],
      ["", "INVALID_STRING_LENGTH"],
      ["not-an-id", "INVALID_STRING_LENGTH"],
      ["0".repeat(29), "INVALID_STRING_CHARS"],
      ["é".repeat(29), "INVALID_STRING_CHARS"],
      [new Uint8Array(17), "INVALID_BINARY_LENGTH"],
      [new ArrayBuffer(0), "INVALID_BINARY_LENGTH"],
    ]
    for (const [input, reason] of cases) {
      assert.equal(vid.verify(input), false)
      assert.deepEqual(vid.verifyDetailed(input), { valid: false, reason }, String(reason))
    }
  })
})

describe("key rotation", () => {
  test("old IDs keep verifying, new IDs use the new version", () => {
    const v1 = VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: 1 })
    const old = v1.generate()

    const v2 = VID.initialize({ keys: { 1: SECRET, 2: OTHER_SECRET }, currentKeyVersion: 2, nodeId: 1 })
    const fresh = v2.generate()

    assert.equal(v2.verify(old), true)
    assert.equal(v2.verify(fresh), true)
    assert.equal(fresh.parse().keyVersion, 2)
    assert.equal(v2.getCurrentKeyVersion(), 2)
    // Higher key versions sort after lower ones, so rotation preserves order.
    assert.equal(VIDValue.compare(old, fresh), -1)
  })

  test("retiring a key revokes the IDs it signed", () => {
    const old = VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: 1 }).generate()
    const v2only = VID.initialize({ keys: { 2: OTHER_SECRET }, currentKeyVersion: 2, nodeId: 1 })
    assert.deepEqual(v2only.verifyDetailed(old), { valid: false, reason: "UNKNOWN_KEY_VERSION" })
  })
})

describe("parse", () => {
  const vid = make()

  test("verifies first by default", () => {
    const id = vid.generate()
    assert.equal(vid.parse(id.toString()).nodeId, 7)

    const forged = make({ keys: { 1: OTHER_SECRET } }).generate()
    assert.throws(() => vid.parse(forged), /SIGNATURE_MISMATCH/)
    assert.equal(vid.parse(forged, { verify: false }).nodeId, 7)
  })

  test("returns a frozen object", () => {
    const meta = vid.parse(vid.generate())
    assert.ok(Object.isFrozen(meta))
  })

  test("rejects structurally broken input with typed errors", () => {
    assert.throws(() => vid.parse("short", { verify: false }), RangeError)
    assert.throws(() => vid.parse(123, { verify: false }), TypeError)
    assert.throws(() => vid.parse(new Uint8Array(18), { verify: false }), /timestamp/)
  })
})

describe("VIDValue", () => {
  const vid = make()

  test("fromString and fromBinary round-trip", () => {
    const id = vid.generate()
    assert.ok(VIDValue.fromString(id.toString()).equals(id))
    assert.ok(VIDValue.fromString(id.toString().toLowerCase()).equals(id))
    assert.ok(VIDValue.fromBinary(id.toBinary()).equals(id))
  })

  test("fromString rejects malformed strings", () => {
    assert.throws(() => VIDValue.fromString("abc"), RangeError)
    assert.throws(() => VIDValue.fromString("1".repeat(29)), /invalid characters/)
    assert.throws(() => VIDValue.fromString(null), TypeError)
  })

  test("is isolated from the bytes it was built from and hands out", () => {
    const bin = vid.generate().toBinary()
    const id = VIDValue.fromBinary(bin)
    const text = id.toString()
    bin.fill(0)
    id.toBinary().fill(0)
    assert.equal(id.toString(), text)
    assert.equal(vid.verify(id), true)
  })

  test("serializes to its string in JSON and in util.inspect", () => {
    const id = vid.generate()
    assert.equal(JSON.stringify({ id }), `{"id":"${id}"}`)
    assert.equal(util.inspect(id), `VIDValue(${id})`)
  })

  test("equals, compare and isVIDValue", () => {
    const a = vid.generate()
    const b = vid.generate()
    assert.equal(a.equals(VIDValue.fromString(String(a))), true)
    assert.equal(a.equals(b), false)
    assert.equal(a.equals("nope"), false)
    assert.deepEqual([b, a].sort(VIDValue.compare), [a, b])
    assert.equal(VIDValue.isVIDValue(a), true)
    assert.equal(VIDValue.isVIDValue(String(a)), false)
  })

  test("parse() decodes without verifying", () => {
    const id = vid.generate()
    assert.deepEqual(id.parse(), vid.parse(id))
  })
})

describe("initialize", () => {
  const bad = [
    [undefined, TypeError, /options is required/],
    [{}, TypeError, /keys is required/],
    [{ keys: {}, currentKeyVersion: 1 }, RangeError, /at least one entry/],
    [{ keys: { 1: "short" }, currentKeyVersion: 1 }, RangeError, /at least 16/],
    [{ keys: { 1: 12345 }, currentKeyVersion: 1 }, TypeError, /must be a string/],
    [{ keys: { 300: SECRET }, currentKeyVersion: 300 }, RangeError, /between 0 and 255/],
    [{ keys: { 1: SECRET }, currentKeyVersion: 2 }, Error, /not present/],
    [{ keys: { 1: SECRET }, currentKeyVersion: 1.5 }, TypeError, /integer/],
    [{ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: 70000 }, RangeError, /0 and 65535/],
    [{ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: "  " }, TypeError, /must not be empty/],
    [{ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: true }, TypeError, /nodeId must be/],
  ]
  for (const [options, type, message] of bad) {
    test(`rejects ${JSON.stringify(options)}`, () => {
      assert.throws(() => VID.initialize(options), (err) => err instanceof type && message.test(err.message))
    })
  }

  test("string node ids hash to a stable uint16", () => {
    const a = make({ nodeId: "pod-backend-1" }).getNodeId()
    const b = make({ nodeId: "pod-backend-1" }).getNodeId()
    assert.equal(a, b)
    assert.ok(Number.isInteger(a) && a >= 0 && a <= 0xffff)
  })
})

describe("auto-detected node id", () => {
  const withEnv = (env, fn) => {
    const saved = { POD_IP: process.env.POD_IP, HOSTNAME: process.env.HOSTNAME }
    Object.assign(process.env, env)
    try {
      return fn()
    } finally {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
    }
  }

  test("is stable within a process and silent", () => {
    withEnv({ HOSTNAME: "web-7d9f" }, () => {
      const warnings = []
      const opts = { keys: { 1: SECRET }, currentKeyVersion: 1, onWarning: (m) => warnings.push(m) }
      assert.equal(VID.initialize(opts).getNodeId(), VID.initialize(opts).getNodeId())
      assert.deepEqual(warnings, [])
    })
  })

  test("differs between worker threads on the same host", async () => {
    const code = `
      const { parentPort } = require("node:worker_threads")
      const { VID } = require(${JSON.stringify(require.resolve("@veridjs/core"))})
      const vid = VID.initialize({ keys: { 1: ${JSON.stringify(SECRET)} }, currentKeyVersion: 1 })
      parentPort.postMessage(vid.getNodeId())
    `
    const run = () =>
      new Promise((resolve, reject) => {
        const worker = new Worker(code, { eval: true, env: { ...process.env, HOSTNAME: "same-host", POD_IP: "" } })
        worker.once("message", resolve)
        worker.once("error", reject)
      })
    const ids = await Promise.all([run(), run(), run()])
    assert.equal(new Set(ids).size, 3, `expected distinct node ids, got ${ids}`)
  })
})
