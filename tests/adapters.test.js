// Postgres and MongoDB adapters, plus the base32 codec they rely on.
const { test, describe } = require("node:test")
const assert = require("node:assert/strict")
const { BSON, Binary } = require("bson")
const { VID, VIDValue } = require("@veridjs/core")
const { VIDPostgresAdapter } = require("@veridjs/core/postgres")
const { VIDMongoAdapter } = require("@veridjs/core/mongo")
const { Base32Encoder } = require("../dist/encoding/Base32Encoder.js")

const vid = VID.initialize({ keys: { 1: "a-test-secret-of-at-least-sixteen-chars" }, currentKeyVersion: 1, nodeId: 3 })

describe("Base32Encoder", () => {
  test("round-trips random binaries", () => {
    for (let i = 0; i < 2_000; i++) {
      const bin = new Uint8Array(require("node:crypto").randomBytes(18))
      const text = Base32Encoder.encode(bin)
      assert.equal(text.length, 29)
      assert.ok(Base32Encoder.isCanonical(text))
      assert.deepEqual(Base32Encoder.decode(text), bin)
    }
  })

  test("rejects a non-zero padding bit", () => {
    const text = Base32Encoder.encode(new Uint8Array(18)) // all "A"
    assert.throws(() => Base32Encoder.decode(text.slice(0, -1) + "B"), /non-canonical/)
  })
})

describe("VIDPostgresAdapter", () => {
  test("round-trips through a BYTEA buffer", () => {
    const id = vid.generate()
    const buf = VIDPostgresAdapter.toDatabase(id)
    assert.ok(Buffer.isBuffer(buf))
    assert.equal(buf.length, 18)
    assert.ok(VIDPostgresAdapter.fromDatabase(buf).equals(id))
    assert.ok(VIDPostgresAdapter.fromDatabase(new Uint8Array(buf)).equals(id))
  })

  test("fromString and toCursor accept a VID string", () => {
    const id = vid.generate()
    assert.deepEqual(VIDPostgresAdapter.fromString(String(id)), VIDPostgresAdapter.toDatabase(id))
    assert.deepEqual(VIDPostgresAdapter.toCursor(String(id)), VIDPostgresAdapter.toDatabase(id))
  })

  test("cursor buffers compare in generation order", () => {
    const a = VIDPostgresAdapter.toDatabase(vid.generate())
    const b = VIDPostgresAdapter.toDatabase(vid.generate())
    assert.equal(Buffer.compare(a, b), -1)
  })

  test("rejects wrong lengths and types", () => {
    assert.throws(() => VIDPostgresAdapter.fromDatabase(Buffer.alloc(16)), RangeError)
    assert.throws(() => VIDPostgresAdapter.fromDatabase(null), TypeError)
    assert.throws(() => VIDPostgresAdapter.toDatabase(new Uint8Array(5)), RangeError)
  })
})

describe("VIDMongoAdapter", () => {
  test("round-trips through BSON serialization", () => {
    const id = vid.generate()
    const doc = BSON.deserialize(BSON.serialize({ _id: VIDMongoAdapter.toDatabase(id) }))
    const back = VIDMongoAdapter.fromDatabase(doc._id)
    assert.ok(back.equals(id))
    assert.equal(vid.verify(back), true)
  })

  test("fromString produces the same Binary as toDatabase", () => {
    const id = vid.generate()
    assert.ok(VIDMongoAdapter.fromString(String(id)).buffer.equals(VIDMongoAdapter.toDatabase(id).buffer))
  })

  test("reads a Binary whose backing buffer is larger than the value", () => {
    const id = vid.generate()
    const grown = new Binary()
    grown.write(Buffer.from(id.toBinary()), 0)
    assert.ok(grown.buffer.length > 18)
    assert.ok(VIDMongoAdapter.fromDatabase(grown).equals(id))
  })

  test("accepts a Binary from another copy of bson (duck-typed)", () => {
    const id = vid.generate()
    const bytes = Buffer.from(id.toBinary())
    const foreign = { _bsontype: "Binary", buffer: bytes, length: () => bytes.length }
    assert.ok(VIDMongoAdapter.fromDatabase(foreign).equals(id))
  })

  test("rejects non-Binary values", () => {
    assert.throws(() => VIDMongoAdapter.fromDatabase(Buffer.alloc(18)), TypeError)
    assert.throws(() => VIDMongoAdapter.fromDatabase(null), TypeError)
  })

  test("toVIDValue is an alias of fromDatabase", () => {
    const binary = VIDMongoAdapter.toDatabase(vid.generate())
    assert.ok(VIDValue.isVIDValue(VIDMongoAdapter.toVIDValue(binary)))
  })
})
