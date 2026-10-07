// Tests for the built package (`npm test` builds first), with Node's own runner: no test framework.
// `/test` is gitignored, so these live in `tests/`.
const { test, beforeEach, afterEach } = require("node:test")
const assert = require("node:assert/strict")
const { VID } = require("@veridjs/core")

const SECRET = "a-test-secret-of-at-least-sixteen-chars"

let calls
let originals

beforeEach(() => {
  calls = { log: [], warn: [], error: [], info: [], debug: [] }
  originals = {}
  for (const level of Object.keys(calls)) {
    originals[level] = console[level]
    console[level] = (...args) => calls[level].push(args)
  }
})

afterEach(() => {
  for (const level of Object.keys(originals)) console[level] = originals[level]
})

const silent = () => Object.values(calls).every((c) => c.length === 0)

test("verify, verifyDetailed and parse print nothing, valid input or not", () => {
  const vid = VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: 7 })
  const id = vid.generate()
  const text = id.toString()
  const forged = text.slice(0, -1) + (text.endsWith("A") ? "B" : "A")

  assert.equal(vid.verify(id), true)
  assert.equal(vid.verify(text), true)
  assert.equal(vid.verify(id.toBinary()), true)
  assert.equal(vid.verify(forged), false)
  assert.equal(vid.verify("not-an-id"), false)
  assert.equal(vid.verify(null), false)
  assert.equal(vid.verifyDetailed(text).valid, true)
  assert.equal(vid.verifyDetailed(forged).valid, false)
  assert.equal(vid.parse(text).nodeId, 7)
  assert.ok(silent(), `expected no console output, got ${JSON.stringify(calls)}`)
})

test("the random-nodeId warning goes to onWarning, not the console", () => {
  const saved = { POD_IP: process.env.POD_IP, HOSTNAME: process.env.HOSTNAME }
  delete process.env.POD_IP
  delete process.env.HOSTNAME
  try {
    const warnings = []
    VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, onWarning: (m) => warnings.push(m) })
    assert.equal(warnings.length, 1)
    assert.match(warnings[0], /nodeId randomly assigned/)
    assert.ok(silent())

    // Without onWarning it still goes to console.warn, as before.
    VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1 })
    assert.equal(calls.warn.length, 1)
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value !== undefined) process.env[key] = value
    }
  }
})

test("an explicit nodeId warns nowhere", () => {
  const warnings = []
  VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, nodeId: "api-1", onWarning: (m) => warnings.push(m) })
  assert.deepEqual(warnings, [])
  assert.ok(silent())
})

test("onWarning must be a function", () => {
  assert.throws(
    () => VID.initialize({ keys: { 1: SECRET }, currentKeyVersion: 1, onWarning: "yes" }),
    /onWarning must be a function/
  )
})

test("every documented entry point resolves", () => {
  assert.equal(typeof require("@veridjs/core").VID, "function")
  for (const path of ["mongo", "adapters/mongo"]) {
    assert.equal(typeof require(`@veridjs/core/${path}`).VIDMongoAdapter, "function", path)
  }
  for (const path of ["postgres", "adapters/postgres"]) {
    assert.equal(typeof require(`@veridjs/core/${path}`).VIDPostgresAdapter, "function", path)
  }
  assert.equal(require("@veridjs/core/package.json").name, "@veridjs/core")
})
