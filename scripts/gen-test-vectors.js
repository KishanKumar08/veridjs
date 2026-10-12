// Writes spec/test-vectors.json.
//
// This is a from-scratch implementation of SPEC.md that does NOT import the
// library, so the vectors check the library against the spec rather than
// against itself. tests/vectors.test.js then runs the library over them.
//
//   node scripts/gen-test-vectors.js
const crypto = require("node:crypto")
const fs = require("node:fs")
const path = require("node:path")

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

const KEYS = {
  0: "vid-test-vector-secret-number-zero",
  1: "vid-test-vector-secret-number-one",
  2: "vid-test-vector-secret-number-two",
  200: "ünïcødé-sëcret-with-multibyte-utf8-✓",
}

const deriveKey = (secret) => crypto.createHash("sha256").update(secret, "utf8").digest()

function payload({ keyVersion, timestamp, nodeId, sequence }) {
  const out = Buffer.alloc(11)
  out.writeUInt8(keyVersion, 0)
  out.writeUIntBE(timestamp, 1, 6)
  out.writeUInt16BE(nodeId, 7)
  out.writeUInt16BE(sequence, 9)
  return out
}

const sign = (data, secret) =>
  crypto.createHmac("sha256", deriveKey(secret)).update(data).digest().subarray(0, 7)

function base32(bytes) {
  let bits = 0
  let value = 0
  let out = ""
  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET[(value >>> bits) & 31]
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

function build(fields, secret = KEYS[fields.keyVersion]) {
  const p = payload(fields)
  const s = sign(p, secret)
  const binary = Buffer.concat([p, s])
  return { payloadHex: p.toString("hex"), signatureHex: s.toString("hex"), binary, string: base32(binary) }
}

function validCase(name, fields) {
  const { payloadHex, signatureHex, binary, string } = build(fields)
  return {
    name,
    ...fields,
    iso: new Date(fields.timestamp).toISOString(),
    payloadHex,
    signatureHex,
    binaryHex: binary.toString("hex"),
    string,
  }
}

const valid = [
  validCase("typical", { keyVersion: 1, timestamp: 1791369154567, nodeId: 42, sequence: 1234 }),
  validCase("minimum timestamp (2020-01-01), other fields zero", { keyVersion: 0, timestamp: 1577836800000, nodeId: 0, sequence: 0 }),
  validCase("all fields at max", { keyVersion: 200, timestamp: 2 ** 48 - 1, nodeId: 65535, sequence: 65535 }),
  validCase("second key version", { keyVersion: 2, timestamp: 1791369154567, nodeId: 42, sequence: 1234 }),
  validCase("multibyte UTF-8 secret", { keyVersion: 200, timestamp: 1700000000000, nodeId: 7, sequence: 9 }),
  validCase("next sequence in same ms", { keyVersion: 1, timestamp: 1791369154567, nodeId: 42, sequence: 1235 }),
  validCase("next millisecond", { keyVersion: 1, timestamp: 1791369154568, nodeId: 42, sequence: 0 }),
]

const typical = valid[0]
const typicalBinary = Buffer.from(typical.binaryHex, "hex")

// Strings a verifier must accept and normalise to the canonical form.
const accepted = [
  { name: "lowercase", input: typical.string.toLowerCase(), canonical: typical.string },
  { name: "surrounding whitespace", input: `  ${typical.string}\n`, canonical: typical.string },
]

function flipBit(buf, byteIndex, mask = 0x01) {
  const copy = Buffer.from(buf)
  copy[byteIndex] ^= mask
  return copy
}

// The last character carries 1 padding bit (29 * 5 = 145 bits for 144 bits of
// data). The canonical form has it set to 0; flipping it decodes to the same
// bytes but must be rejected.
const lastIndex = ALPHABET.indexOf(typical.string.at(-1))
const nonCanonical = typical.string.slice(0, -1) + ALPHABET[lastIndex | 1]

const unknownVersion = build({ keyVersion: 9, timestamp: 1791369154567, nodeId: 42, sequence: 1234 }, "a-key-the-verifier-does-not-have")
const wrongSecret = build({ keyVersion: 1, timestamp: 1791369154567, nodeId: 42, sequence: 1234 }, "a-different-secret-for-version-1")

const invalid = [
  { name: "signature bit flipped", inputHex: flipBit(typicalBinary, 17).toString("hex"), reason: "SIGNATURE_MISMATCH" },
  { name: "timestamp tampered", inputHex: flipBit(typicalBinary, 6).toString("hex"), reason: "SIGNATURE_MISMATCH" },
  { name: "nodeId tampered", inputHex: flipBit(typicalBinary, 8).toString("hex"), reason: "SIGNATURE_MISMATCH" },
  { name: "sequence tampered", inputHex: flipBit(typicalBinary, 10).toString("hex"), reason: "SIGNATURE_MISMATCH" },
  { name: "signed with a different secret", input: wrongSecret.string, reason: "SIGNATURE_MISMATCH" },
  { name: "tampered string", input: base32(flipBit(typicalBinary, 3)), reason: "SIGNATURE_MISMATCH" },
  { name: "unknown key version", input: unknownVersion.string, reason: "UNKNOWN_KEY_VERSION" },
  { name: "non-canonical padding bit", input: nonCanonical, reason: "NON_CANONICAL_STRING" },
  { name: "string too short", input: typical.string.slice(0, 28), reason: "INVALID_STRING_LENGTH" },
  { name: "string too long", input: typical.string + "A", reason: "INVALID_STRING_LENGTH" },
  { name: "character outside alphabet (0)", input: "0" + typical.string.slice(1), reason: "INVALID_STRING_CHARS" },
  { name: "character outside alphabet (8)", input: typical.string.slice(0, 10) + "8" + typical.string.slice(11), reason: "INVALID_STRING_CHARS" },
  { name: "UUID string", input: "018f4c2a-7b3e-7c1d-9a2b-3c4d5e6f7a8b", reason: "INVALID_STRING_LENGTH" },
  { name: "binary too short", inputHex: typicalBinary.subarray(0, 17).toString("hex"), reason: "INVALID_BINARY_LENGTH" },
  { name: "binary too long", inputHex: Buffer.concat([typicalBinary, Buffer.from([0])]).toString("hex"), reason: "INVALID_BINARY_LENGTH" },
]

const vectors = {
  spec: "SPEC.md",
  formatVersion: 1,
  note: "Generated by scripts/gen-test-vectors.js. String inputs use `input`, binary inputs use `inputHex`.",
  keys: KEYS,
  valid,
  accepted,
  invalid,
}

const outFile = path.join(__dirname, "..", "spec", "test-vectors.json")
fs.writeFileSync(outFile, JSON.stringify(vectors, null, 2) + "\n")
console.log(`Wrote ${valid.length} valid, ${accepted.length} accepted and ${invalid.length} invalid vectors to ${path.relative(process.cwd(), outFile)}`)
