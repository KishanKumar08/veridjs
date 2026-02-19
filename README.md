# `@veridjs/core`

**Cryptographically verifiable, globally unique, time-sortable identifiers.**

[![npm](https://img.shields.io/npm/v/@vidjs/core?color=crimson&style=flat-square)](https://www.npmjs.com/package/@vidjs/core)
[![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](#)

---

UUID tells you an ID is unique. **VID tells you an ID is yours.**

Every VID embeds an HMAC-SHA256 signature. Your server can verify — in a single synchronous call, without touching the database — that an ID was legitimately issued by your system and has not been tampered with. Random IDs, forged IDs, and enumeration attempts are rejected before any query runs.

```
┌────────────┬───────────┬────────┬──────────┬───────────┐
│ KeyVersion │ Timestamp │ NodeId │ Sequence │ Signature │
│   1 byte   │  6 bytes  │ 2 bytes│  2 bytes │  7 bytes  │
└────────────┴───────────┴────────┴──────────┴───────────┘
                         18 bytes total
```

---

## Why not UUID?

| | UUIDv4 | UUIDv7 | Snowflake | **VID** |
|---|:---:|:---:|:---:|:---:|
| Globally unique | ✅ | ✅ | ✅ | ✅ |
| Time-sortable | ❌ | ✅ | ✅ | ✅ |
| Cryptographically verifiable | ❌ | ❌ | ❌ | ✅ |
| Forgery-resistant | ❌ | ❌ | ❌ | ✅ |
| No coordination service needed | ✅ | ✅ | ❌ | ✅ |
| Key rotation | ❌ | ❌ | ❌ | ✅ |
| Binary size | 16 B | 16 B | 8 B | **18 B** |
| Zero dependencies | ✅ | ✅ | varies | ✅ |

VID is 2 bytes larger than UUIDv7 binary. Those 2 bytes buy you something no other identifier format in this table offers: **proof of origin**.

---

## Installation

```bash
npm install @veridjs/core
```

**Node.js ≥ 18 required.** Zero runtime dependencies — only Node's built-in `crypto` module.

---

## Quick start

```ts
import { VID } from "@veridjs/core"

// Create once at application startup — reuse everywhere
const vid = VID.initialize({
  keys: { 1: process.env.VID_SECRET! },
  currentKeyVersion: 1,
  nodeId: "pod-backend-us-east-1a", // Optional
})

// Generate
const id = vid.generate()
console.log(id.toString())  // "AEAZY4DVF7PQAKQAADFM7JS2DIBBQ"  (29 chars)
console.log(id.toBinary())  // Uint8Array(18)

// Verify — boolean, never throws, constant-time
const ok = vid.verify(id)

// Parse metadata (verifies signature first by default)
const meta = vid.parse(id)
console.log(meta.iso)       // "2026-02-18T10:12:34.567Z"
console.log(meta.nodeId)    // 4319  (stable hash of your string)
console.log(meta.sequence)  // 0
```

---

## Initialization

```ts
const vid = VID.initialize({
  keys: { 1: process.env.VID_SECRET! },
  currentKeyVersion: 1,
  nodeId: "pod-backend-7d9f",  // optional — see Node Identity
})
```

| Option | Type | Required | Description |
|---|---|:---:|---|
| `keys` | `Record<number, string>` | ✅ | Map of `keyVersion → secret string`. Min 16 chars per secret. |
| `currentKeyVersion` | `number` | ✅ | Version used for new IDs. Must exist in `keys`. Range: 0–255. |
| `nodeId` | `number \| string` | — | Instance identifier. Accepts 0–65535 or any string. Auto-detected if omitted. |

> **Secret management:** Never hardcode secrets. Use `process.env.VID_SECRET` or a secrets manager. Secrets are hashed to 32-byte keys internally — they are never stored or logged.

---

## API reference

### `vid.generate()` → `VIDValue`

Generates a new VID. **Synchronous** — no async, no I/O, no await.

```ts
const id = vid.generate()
```

- Up to **65,536 unique IDs per millisecond per node** before the generator waits for the next clock tick
- Sequence never wraps silently — overflow blocks until the clock advances (max 5 second wait, then throws)
- Each instance maintains its own sequence counter — share one `VID` instance per process

---

### `vid.verify(input)` → `boolean`

Verifies the HMAC-SHA256 signature embedded in the ID. **Always returns `boolean`, never throws.**

```ts
vid.verify(id)                              // VIDValue
vid.verify("AEAZY4DVF7PQAKQAADFM7JS2DIBBQ") // base32 string
vid.verify(id.toBinary())                   // Uint8Array
vid.verify(buffer)                          // Node.js Buffer
vid.verify(arrayBuffer)                     // ArrayBuffer
```

Uses `crypto.timingSafeEqual` internally — immune to timing side-channel attacks.

---

### `vid.parse(input, options?)` → `VIDMetadata`

Decodes the ID into structured fields. **Verifies the signature first by default.**

```ts
const meta = vid.parse(id)
// {
//   keyVersion: 1,
//   timestamp:  1708251234567,      // Unix ms — when the ID was generated
//   date:       Date object,
//   iso:        "2026-02-18T10:12:34.567Z",
//   nodeId:     4319,               // resolved uint16 of your string
//   sequence:   0,
// }

// If you already verified earlier in the pipeline, skip the second HMAC:
const meta = vid.parse(id, { verify: false })
```

> ⚠️ Never use `{ verify: false }` on input from an untrusted source.

---

### `vid.verifyDetailed(input)` → `VerifyResult`

Returns a typed result with a failure reason. **For internal logging only — never expose the reason to API clients.**

```ts
const result = vid.verifyDetailed(req.params.id)

if (!result.valid) {
  logger.warn("VID rejected", { reason: result.reason, path: req.path })
  // reason: "NULL_INPUT" | "INVALID_STRING_LENGTH" | "INVALID_STRING_CHARS"
  //       | "INVALID_BINARY_LENGTH" | "UNKNOWN_KEY_VERSION" | "SIGNATURE_MISMATCH"

  return res.status(400).json({ error: "Invalid ID" }) // generic to client
}
```

---

### `VIDValue`

The object returned by `vid.generate()` and the static factories.

```ts
id.toString()            // "AEAZY4DVF7PQAKQAADFM7JS2DIBBQ"  — 29-char base32 string
id.toBinary()            // Uint8Array(18) — fresh defensive copy each call
id.parse()               // VIDMetadata — structural decode, no signature check
id.equals(other)         // byte-for-byte equality

VIDValue.fromString("AEAZY4DVF7PQAKQAADFM7JS2DIBBQ")  // parse a received string
VIDValue.fromBinary(uint8Array)                         // wrap raw database bytes
VIDValue.isVIDValue(value)                              // TypeScript type guard
```

> **Sort order:** VID binary fields sort chronologically — `ORDER BY id ASC` in PostgreSQL or MongoDB is time order. **Base32 strings are not directly string-sortable** (the alphabet `A–Z,2–7` does not align with ASCII order). Always sort by the binary column or the extracted timestamp, never by the string representation.

---

## Key rotation

Add the new key alongside the old one. Old IDs remain verifiable. The `keyVersion` byte embedded in every ID tells the verifier which key to use automatically.

```ts
// Step 1 — currently on version 1
const vid = VID.initialize({
  keys: { 1: process.env.VID_SECRET_V1! },
  currentKeyVersion: 1,
})

// Step 2 — rotate: new IDs use v2, old v1 IDs still verify
const vid = VID.initialize({
  keys: {
    1: process.env.VID_SECRET_V1!,   // retained — old IDs still verifiable
    2: process.env.VID_SECRET_V2!,   // new IDs use this
  },
  currentKeyVersion: 2,
})

// Step 3 — once all v1 IDs have expired from your system, remove v1
const vid = VID.initialize({
  keys: { 2: process.env.VID_SECRET_V2! },
  currentKeyVersion: 2,
})
```

---

## Node identity

VID embeds a `nodeId` (0–65535) in every ID to prevent collisions across concurrent instances generating IDs in the same millisecond. Resolution runs in this priority order:

| Priority | Source | Notes |
|:---:|---|---|
| 1 | `nodeId` in config (number) | Most explicit. Best for static deployments. |
| 2 | `nodeId` in config (string) | SHA-256 hashed to a stable uint16. Deterministic across restarts. |
| 3 | `POD_IP` env var | Kubernetes Downward API — unique per pod. |
| 4 | `HOSTNAME` env var | Docker / ECS — unique per container. |
| 5 | Random + **warning logged** | Safe only for single-instance deployments. |

**Kubernetes (recommended for production):**

```yaml
# Inject the pod's IP as an env var — unique per pod, no coordination needed
env:
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
```

```ts
// VID picks it up automatically
const vid = VID.initialize({
  keys: { 1: process.env.VID_SECRET! },
  currentKeyVersion: 1,
  // no nodeId needed — POD_IP is detected automatically
})
```

> ⚠️ If two running instances resolve to the same `nodeId` and generate IDs in the same millisecond, a collision is possible. Ensure your nodeId assignment is unique across all concurrently running instances.

---

## Database integration

### MongoDB

VID stores as BSON Binary — 18 bytes on disk per ID, no string encoding overhead.

```ts
import { VIDMongoAdapter } from "@vidjs/core/adapters/mongo"

// Insert
await collection.insertOne({
  _id:   VIDMongoAdapter.toDatabase(vid.generate()),  // VIDValue → BSON Binary
  email: "user@example.com",
})

// Query by ID from URL param or request body
const binary = VIDMongoAdapter.fromString(req.params.id)
const doc    = await collection.findOne({ _id: binary })
if (!doc) return res.status(404).send()

// Load and verify the returned document ID
const id      = VIDMongoAdapter.fromDatabase(doc._id)
const isValid = vid.verify(id)
const meta    = vid.parse(id, { verify: false })  // already verified above
```

**Mongoose schema:**
```ts
const userSchema = new Schema({
  _id: {
    type:    Buffer,
    default: () => VIDMongoAdapter.toDatabase(vid.generate()),
  }
})
```

---

### PostgreSQL

VID stores as `BYTEA` — 18 bytes per row. B-tree index on `BYTEA` sorts chronologically, enabling native time-range queries and O(log n) cursor pagination without a separate `created_at` column.

```sql
CREATE TABLE users (
  id    BYTEA PRIMARY KEY,
  email TEXT  NOT NULL
);
```

```ts
import { VIDPostgresAdapter } from "@vidjs/core/adapters/postgres"

// Insert
await db.query(
  "INSERT INTO users (id, email) VALUES ($1, $2)",
  [VIDPostgresAdapter.toDatabase(vid.generate()), "user@example.com"]
)

// Query by string ID
const result = await db.query(
  "SELECT * FROM users WHERE id = $1",
  [VIDPostgresAdapter.fromString(req.params.id)]
)

// Cursor-based pagination — no OFFSET, efficient at any page depth
const rows = await db.query(
  `SELECT id, email FROM users
   WHERE id > $1
   ORDER BY id ASC
   LIMIT 50`,
  [VIDPostgresAdapter.toCursor(req.query.after)]
)

// Convert returned rows back to VIDValue
const id   = VIDPostgresAdapter.fromDatabase(rows[0].id)
const meta = vid.parse(id)
```

---

## Benchmark — 1 million rows in MongoDB

Machine: single-node MongoDB. Collection contains only the identifier field and one additional text field. All benchmarks use the same hardware, same data volume, same query pattern (lookup by primary key).

```
uuidv4_string     Inserted: 1,000,000   Insert: 14,515 ms   Index: 57.21 MB   Coll: 70.57 MB   Query: 29 ms
uuidv7_string     Inserted: 1,000,000   Insert:  9,397 ms   Index: 16.33 MB   Coll: 70.57 MB   Query:  4 ms
vid (binary)      Inserted: 1,000,000   Insert:  7,050 ms   Index: 22.85 MB   Coll:  ~6.2 MB   Query: ~4 ms
```

| | UUIDv4 string | UUIDv7 string | VID binary |
|---|---:|---:|---:|
| **Insert time** | 14,515 ms | 9,397 ms | **7,050 ms** |
| **Index size** | 57.21 MB | 16.33 MB | 22.85 MB |
| **Collection size** | 70.57 MB | 70.57 MB | **~6.2 MB** |
| **Query time** | 29 ms | 4 ms | **~4 ms** |

### What the numbers mean

**51% faster inserts than UUIDv4.**
UUIDv4 is completely random — inserts scatter across the entire B-tree index causing constant page splits and cache evictions. VID's time-prefixed binary keeps new inserts at the right edge of the index, like an auto-increment ID would, while still being globally unique without a sequence table.

**25% faster inserts than UUIDv7 string.**
Both are time-sorted. The difference is data volume: UUIDv7 stored as a 36-character UTF-8 string writes ~36 bytes per index key. VID binary writes 18 bytes. Half the index key size means more keys fit in a B-tree node, fewer nodes to traverse, and fewer disk pages written on insert.

**91% smaller collection than UUIDv4/v7 string.**
String storage encodes each identifier as ~36–38 UTF-8 bytes plus BSON string overhead. VID binary stores 18 raw bytes plus BSON Binary overhead. At one million rows the difference is ~64 MB. At 100 million rows that difference is working set that either fits in RAM or doesn't.

**Index 60% larger than UUIDv7 string despite smaller binary.**
VID's index is 22.85 MB vs UUIDv7's 16.33 MB because UUIDv7 binary is 16 bytes while VID is 18 bytes — the 2-byte difference is the cost of the embedded key version and sequence field that enable authenticity verification and multi-instance uniqueness. This is the documented trade-off.

> **Reproducibility:** The `vid_string` benchmark label in the raw output is a misnomer — VID was benchmarked in binary (BSON Binary) mode, not string mode. The collection size reflects binary storage. Collection size was truncated in the original output at `6` — the `~6.2 MB` figure above is an estimate; the exact number will be in the published benchmark repository.

---

## Security model

### What VID guarantees

- ✅ The ID was produced by a system holding the correct secret key
- ✅ No byte in the ID has been modified since generation
- ✅ Cross-instance uniqueness (assuming unique nodeIds across concurrent instances)
- ✅ Time-sortability — binary sort order equals generation order

### What VID does not guarantee

- ❌ **Replay protection** — a valid ID captured in transit can be reused. Add a seen-ID store (e.g. Redis `SET NX` with TTL) if replay attacks are a concern
- ❌ **Ownership** — VID does not prove an ID belongs to a specific user. That is your application's responsibility
- ❌ **Freshness** — VID does not reject old IDs. Check `meta.timestamp` if you need a freshness window

### Cryptographic parameters

| Parameter | Value | Notes |
|---|---|---|
| Algorithm | HMAC-SHA256 | Standard, widely audited |
| Signature | 7 bytes (56 bits) | ~72 quadrillion possible values |
| Key derivation | SHA-256 of raw secret | 32-byte key, raw secret never stored |
| Comparison | `crypto.timingSafeEqual` | No timing side-channel |
| Random forgery probability | 1 in 72,057,594,037,927,936 | Per attempt, no precomputation possible |

Pair VID with API-level rate limiting to make targeted brute-force computationally infeasible.

### Security disclosure

Please **do not open a public GitHub issue** for security vulnerabilities. Email `kmali4551@gmail.com` directly. Public issues announce the vulnerability to attackers before a patch is available.

---

## Express middleware pattern

```ts
// Authenticate every VID in route params automatically
app.param("id", (req, res, next, rawId) => {
  const result = vid.verifyDetailed(rawId)

  if (!result.valid) {
    logger.warn("VID rejected", { reason: result.reason, ip: req.ip })
    return res.status(400).json({ error: "Invalid ID" })
  }

  req.vidMeta = vid.parse(rawId, { verify: false }) // already verified above
  next()
})

app.get("/users/:id", async (req, res) => {
  const { nodeId, timestamp } = req.vidMeta
  // ID is authenticated — safe to query
  const user = await db.users.findById(req.params.id)
  res.json(user)
})
```

---

## Environment variables

| Variable | Purpose |
|---|---|
| `VID_SECRET` | Primary secret key (min 16 chars) |
| `VID_SECRET_V2` | New secret during rotation |
| `POD_IP` | Auto-detected in Kubernetes for `nodeId` (inject via Downward API) |
| `HOSTNAME` | Auto-detected in Docker/ECS for `nodeId` |
| `NODE_ENV=production` | Prevents test clock overrides (`TimeUtils.setNowProvider`) from running |

---

## Diagnostics

```ts
logger.info("VID engine ready", {
  nodeId:     vid.getNodeId(),            // the uint16 embedded in every generated ID
  keyVersion: vid.getCurrentKeyVersion(), // version used for new IDs
})
```

Log this at startup. If `nodeId` changes between deploys unexpectedly, it means your nodeId source (env var or string) changed — old IDs still verify, but you will want to understand why the node identity shifted.

---

## License

MIT — see [LICENSE](./LICENSE)

---

## Contributing

Pull requests and issues welcome on [GitHub](https://github.com/KishanKumar08/veridjs).

For security vulnerabilities, email privately — do not open a public issue.