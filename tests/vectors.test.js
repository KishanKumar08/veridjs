// Runs the library over spec/test-vectors.json. The vectors come from an
// independent implementation of SPEC.md (scripts/gen-test-vectors.js), so a
// failure here means the library and the spec disagree.
const { test } = require("node:test")
const assert = require("node:assert/strict")
const { VID, VIDValue } = require("@veridjs/core")
const vectors = require("../spec/test-vectors.json")

const vid = VID.initialize({ keys: vectors.keys, currentKeyVersion: 1, nodeId: 1 })

const inputOf = (v) => (v.inputHex !== undefined ? Buffer.from(v.inputHex, "hex") : v.input)

for (const v of vectors.valid) {
  test(`valid vector: ${v.name}`, () => {
    const binary = Buffer.from(v.binaryHex, "hex")

    assert.equal(vid.verify(v.string), true)
    assert.equal(vid.verify(binary), true)
    assert.equal(VIDValue.fromString(v.string).toString(), v.string)
    assert.equal(Buffer.from(VIDValue.fromString(v.string).toBinary()).toString("hex"), v.binaryHex)

    const meta = vid.parse(v.string)
    assert.equal(meta.keyVersion, v.keyVersion)
    assert.equal(meta.timestamp, v.timestamp)
    assert.equal(meta.nodeId, v.nodeId)
    assert.equal(meta.sequence, v.sequence)
    assert.equal(meta.iso, v.iso)
  })
}

for (const v of vectors.accepted) {
  test(`accepted vector: ${v.name}`, () => {
    assert.equal(vid.verify(v.input), true)
    assert.equal(VIDValue.fromString(v.input).toString(), v.canonical)
  })
}

for (const v of vectors.invalid) {
  test(`invalid vector: ${v.name}`, () => {
    const input = inputOf(v)
    assert.equal(vid.verify(input), false)
    assert.deepEqual(vid.verifyDetailed(input), { valid: false, reason: v.reason })
  })
}

test("vectors are ordered: binary order matches generation order", () => {
  const [typical, , , , , nextSeq, nextMs] = vectors.valid
  const a = Buffer.from(typical.binaryHex, "hex")
  assert.equal(Buffer.compare(a, Buffer.from(nextSeq.binaryHex, "hex")), -1)
  assert.equal(Buffer.compare(a, Buffer.from(nextMs.binaryHex, "hex")), -1)
})
