// Throughput of generate / verify / parse next to crypto.randomUUID, on the built package.
// Run: npm run bench
const crypto = require("node:crypto")
const { VID } = require("..")

const vid = VID.initialize({ keys: { 1: "bench-secret-bench-secret-bench" }, currentKeyVersion: 1, nodeId: 1 })
const N = 200_000

function bench(name, fn) {
  for (let i = 0; i < 20_000; i++) fn(i) // warm up the JIT
  const start = process.hrtime.bigint()
  for (let i = 0; i < N; i++) fn(i)
  const ns = Number(process.hrtime.bigint() - start) / N
  return { operation: name, "ns/op": Math.round(ns), "ops/sec": Math.round(1e9 / ns).toLocaleString("en-US") }
}

const ids = Array.from({ length: N }, () => vid.generate())
const strings = ids.map(String)
const binaries = ids.map((id) => id.toBinary())

console.log(`Node ${process.version} · ${process.platform}/${process.arch}\n`)
console.table([
  bench("crypto.randomUUID()", () => crypto.randomUUID()),
  bench("vid.generate()", () => vid.generate()),
  bench("vid.generate().toString()", () => vid.generate().toString()),
  bench("vid.verify(string)", (i) => vid.verify(strings[i])),
  bench("vid.verify(binary)", (i) => vid.verify(binaries[i])),
  bench("vid.parse(string)", (i) => vid.parse(strings[i])),
])
