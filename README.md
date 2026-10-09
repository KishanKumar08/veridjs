<div align="center">

# VID · `@veridjs/core`

**IDs that prove they're yours.**

Signed, time-sortable identifiers for Node.js. Check that an ID came from your servers with one synchronous call, before it ever touches your database.

[![npm](https://img.shields.io/npm/v/@veridjs/core?color=crimson&style=flat-square)](https://www.npmjs.com/package/@veridjs/core)
[![CI](https://img.shields.io/github/actions/workflow/status/KishanKumar08/veridjs/ci.yml?branch=master&style=flat-square&label=tests)](https://github.com/KishanKumar08/veridjs/actions/workflows/ci.yml)
[![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](./package.json)
[![types](https://img.shields.io/badge/types-included-blue?style=flat-square)](./src/index.ts)
[![license](https://img.shields.io/npm/l/@veridjs/core?style=flat-square)](./LICENSE)

</div>

```ts
const id = vid.generate()            // AEAZY4DVF7PQAKQAADFM7JS2DIBBQ

vid.verify(id)                       // true
vid.verify("AEAZY4DVF7PQAKQAADFM7JS2DIBBA")  // false: forged, rejected in ~3 µs, no DB query
```

---

## Why

A UUID tells you an ID is **unique**. It can't tell you whether the ID is **real**.

So every `GET /orders/:id` with a made-up ID costs you a database round-trip, a cache miss, and a log line. Bots that scan IDs, broken clients, and fuzzers all get to hit your database for free.

VID puts an HMAC-SHA256 signature inside the ID. Your API can reject anything your servers didn't issue **at the edge, in memory, in microseconds**, and still get everything you like about UUIDv7: time-ordered, index-friendly, no coordination service.

```
┌────────────┬───────────┬────────┬──────────┬───────────┐
│ KeyVersion │ Timestamp │ NodeId │ Sequence │ Signature │
│   1 byte   │  6 bytes  │ 2 bytes│  2 bytes │  7 bytes  │
└────────────┴───────────┴────────┴──────────┴───────────┘
      18 bytes binary  ·  29 characters base32
```

### Good fits

- **Public APIs and URLs.** Drop junk and enumeration traffic before it reaches Postgres, Mongo or Redis.
- **IDs that cross trust boundaries:** webhooks, callback URLs, IDs passed between microservices, IDs coming back from the browser.
- **Cache-stampede protection.** Random IDs can't create cache misses because they never pass `verify()`.
- **Multi-region writes.** Time-sortable and unique without a central sequence or Snowflake coordinator.

### Not a fit

- **Secrets or access tokens.** VID is signed, not encrypted: the timestamp is readable by anyone. A valid ID is not permission to access the resource.
- **The smallest possible key.** At 18 bytes, VID is 2 bytes larger than a UUID.
- **Lexicographically sortable strings.** Sort by the binary column instead (see [Sorting](#sorting)).

---

## Install

```bash
npm install @veridjs/core
```

Node.js ≥ 18. **Zero runtime dependencies**: it uses only `node:crypto`. Ships CommonJS and TypeScript types and works with `import` in ESM.

## Quick start

```ts
import { VID } from "@veridjs/core"

// Once, at startup. Reuse the instance everywhere.
export const vid = VID.initialize({
  keys: { 1: process.env.VID_SECRET! },  // ≥ 16 chars; use 32+ random bytes
  currentKeyVersion: 1,
})

const id = vid.generate()
id.toString()      // "AEAZY4DVF7PQAKQAADFM7JS2DIBBQ"
id.toBinary()      // Uint8Array(18), for your primary key column
JSON.stringify({ id })  // '{"id":"AEAZY4DVF7PQAKQAADFM7JS2DIBBQ"}'

vid.verify(req.params.id)  // boolean, never throws, constant-time

const meta = vid.parse(id) // verifies, then decodes
meta.iso                   // "2026-10-07T10:32:34.567Z"
```

Generate a secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

---

## How it compares

| | UUIDv4 | UUIDv7 | ULID | Snowflake | **VID** |
|---|:---:|:---:|:---:|:---:|:---:|
| Unique without coordination | ✅ | ✅ | ✅ | ❌ | ✅ |
| Time-ordered binary / index locality | ❌ | ✅ | ✅ | ✅ | ✅ |
| Lexicographically sortable string | ❌ | ✅ | ✅ | ✅ | ❌ |
| **Rejects forged / random IDs offline** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Key rotation & revocation** | — | — | — | — | ✅ |
| Binary size | 16 B | 16 B | 16 B | 8 B | 18 B |
| String length | 36 | 36 | 26 | ≤ 20 | 29 |

VID costs 2 extra bytes and one HMAC per ID. In return, every ID carries **proof of origin**.

## Performance

`npm run bench` on an Apple M-series laptop, Node 20:

| Operation | Time | Throughput |
|---|---:|---:|
| `crypto.randomUUID()` (baseline) | 0.07 µs | 14 M/s |
| `vid.generate()` | 2.7 µs | 365 k/s |
| `vid.verify(string)` | 3.7 µs | 270 k/s |
| `vid.verify(binary)` | 3.4 µs | 290 k/s |

Almost all of that time is one HMAC-SHA256 call in Node's crypto. In practice, `verify()` is ~100× cheaper than the database round-trip it saves. Run the benchmark on your own hardware; the numbers vary.

---

## API

### `VID.initialize(options)` → `VID`

| Option | Type | Required | Description |
|---|---|:---:|---|
| `keys` | `Record<number, string>` | ✅ | `keyVersion → secret`. Versions 0–255, secrets ≥ 16 UTF-8 bytes. |
| `currentKeyVersion` | `number` | ✅ | Version used for new IDs. Must exist in `keys`. |
| `nodeId` | `number \| string` | — | Unique per running generator. 0–65535 or any string. Auto-detected if omitted ([details](#node-identity)). |
| `onWarning` | `(message) => void` | — | Receives configuration warnings instead of `console.warn`. |

Misconfiguration throws at startup with a message that says how to fix it. Secrets are SHA-256-derived into 32-byte keys and the raw string is never stored.

### `vid.generate()` → `VIDValue`

Synchronous, no I/O. Monotonic within the instance, even if the system clock steps backwards. Each instance can produce at least 32,768 IDs per millisecond. Past that it waits for the next millisecond and never wraps.

### `vid.verify(input)` → `boolean`

Accepts a `string` (case-insensitive, whitespace trimmed), `Uint8Array`, `Buffer`, `ArrayBuffer` or `VIDValue`. **Never throws.** Uses `crypto.timingSafeEqual`.

### `vid.verifyDetailed(input)` → `{ valid: true } | { valid: false, reason }`

For logs and metrics. Possible `reason` values:

`NULL_INPUT` · `UNSUPPORTED_TYPE` · `INVALID_STRING_LENGTH` · `INVALID_STRING_CHARS` · `NON_CANONICAL_STRING` · `INVALID_BINARY_LENGTH` · `UNKNOWN_KEY_VERSION` · `SIGNATURE_MISMATCH`

> Log the reason internally, but return a generic `400 Invalid ID` to clients.

### `vid.parse(input, { verify = true })` → `VIDMetadata`

```ts
{ keyVersion: 1, timestamp: 1791369154567, date: Date, iso: "2026-10-07T10:32:34.567Z", nodeId: 4319, sequence: 18211 }
```

Verifies first and throws if verification fails. Pass `{ verify: false }` only if you already verified the same input.

### `VIDValue`

```ts
import { VIDValue } from "@veridjs/core"

id.toString()               // 29-char base32 (cached)
id.toBinary()               // fresh Uint8Array(18) copy
id.toJSON()                 // same as toString(), so res.json({ id }) just works
id.parse()                  // decode fields WITHOUT verifying
id.equals(other)            // byte equality

VIDValue.fromString(str)    // parse a string (format check only, no signature check)
VIDValue.fromBinary(bytes)  // wrap bytes from your database
VIDValue.compare(a, b)      // sort comparator: ids.sort(VIDValue.compare)
VIDValue.isVIDValue(x)      // type guard
```

### Diagnostics

```ts
logger.info("VID ready", { nodeId: vid.getNodeId(), keyVersion: vid.getCurrentKeyVersion() })
```

---

## Recipes

### Express

```ts
app.param("id", (req, res, next, raw) => {
  const result = vid.verifyDetailed(raw)
  if (!result.valid) {
    logger.warn({ reason: result.reason, ip: req.ip }, "VID rejected")
    return res.status(400).json({ error: "Invalid ID" })
  }
  next()
})

app.get("/orders/:id", async (req, res) => {
  // Only IDs your servers issued reach this line.
  res.json(await orders.findById(req.params.id))
})
```

### Fastify

```ts
fastify.addHook("preHandler", async (req, reply) => {
  const id = (req.params as { id?: string }).id
  if (id !== undefined && !vid.verify(id)) {
    return reply.code(400).send({ error: "Invalid ID" })
  }
})
```

### Next.js route handler (Node.js runtime)

```ts
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  if (!vid.verify(params.id)) return Response.json({ error: "Invalid ID" }, { status: 400 })
  return Response.json(await getOrder(params.id))
}
```

### Zod

```ts
const VidString = z.string().refine((s) => vid.verify(s), "Invalid ID")
```

### Short-lived links (freshness)

```ts
const { timestamp } = vid.parse(token)
if (Date.now() - timestamp > 15 * 60_000) throw new Error("Link expired")
```

---

## Databases

Store IDs as **binary (18 bytes)**, not as strings. Binary is smaller, indexes better and sorts by time.

### PostgreSQL

```sql
CREATE TABLE orders (
  id    BYTEA PRIMARY KEY CHECK (octet_length(id) = 18),
  total INTEGER NOT NULL
);
```

```ts
import { VIDPostgresAdapter as PG } from "@veridjs/core/postgres"

await db.query("INSERT INTO orders (id, total) VALUES ($1, $2)", [PG.toDatabase(vid.generate()), 4200])

// Look up by the string a client sent you (verify first!)
if (!vid.verify(req.params.id)) return res.status(400).end()
const { rows } = await db.query("SELECT * FROM orders WHERE id = $1", [PG.fromString(req.params.id)])

// Keyset pagination: no OFFSET, fast at any depth
const page = await db.query(
  "SELECT id, total FROM orders WHERE id > $1 ORDER BY id LIMIT 50",
  [PG.toCursor(req.query.after)]
)
const items = page.rows.map((r) => ({ id: PG.fromDatabase(r.id).toString(), total: r.total }))
```

### MongoDB

```ts
import { VIDMongoAdapter as Mongo } from "@veridjs/core/mongo"  // needs `bson` (ships with the mongodb driver)

await orders.insertOne({ _id: Mongo.toDatabase(vid.generate()), total: 4200 })

if (!vid.verify(req.params.id)) return res.status(400).end()
const doc = await orders.findOne({ _id: Mongo.fromString(req.params.id) })
const id  = Mongo.fromDatabase(doc._id)   // works with the driver's own bson copy
```

**Mongoose:**

```ts
const orderSchema = new Schema({
  _id: { type: Buffer, default: () => Buffer.from(vid.generate().toBinary()) },
})
```

### Prisma / Drizzle / Kysely

Use a `Bytes` / `bytea` column and pass `Buffer.from(id.toBinary())`. Read it back with `VIDValue.fromBinary(row.id)`.

### Sorting

Binary VIDs sort in time order, so `ORDER BY id` is chronological. **Base32 strings do not sort** this way (the RFC 4648 alphabet isn't in ASCII order). Sort by the binary column, by `meta.timestamp`, or in JavaScript with `ids.sort(VIDValue.compare)`.

The first byte is the key version, so always rotate **upwards** (1 → 2 → 3). Rotating upwards keeps IDs signed with a newer key sorting after older ones.

---

## Key rotation

The key version travels inside every ID, so verification always picks the right key.

```ts
// 1. Today
VID.initialize({ keys: { 1: V1 }, currentKeyVersion: 1 })

// 2. Rotate: new IDs use v2, existing v1 IDs still verify
VID.initialize({ keys: { 1: V1, 2: V2 }, currentKeyVersion: 2 })

// 3. Revoke: drop v1 and every ID it signed stops verifying (reason: UNKNOWN_KEY_VERSION)
VID.initialize({ keys: { 2: V2 }, currentKeyVersion: 2 })
```

Leaked secret? Rotate immediately and decide whether to keep the old version for verification or revoke it.

---

## Node identity

Two generators may only share a `nodeId` if they never run at the same time. Resolution order:

| # | Source | Notes |
|:---:|---|---|
| 1 | `nodeId: 42` | Explicit, no hashing. **Best for large fleets.** |
| 2 | `nodeId: "api-7d9f"` | SHA-256 → uint16. Stable across restarts. |
| 3 | `POD_IP` env | Kubernetes Downward API, combined with process id and thread id. |
| 4 | `HOSTNAME` env | Docker / ECS / VMs, combined with process id and thread id. |
| 5 | Random | Warns via `onWarning` / `console.warn`. Single instance only. |

Options 3 and 4 include the process id and thread id, so **cluster mode, PM2 and `worker_threads` work out of the box.**

**How likely are collisions?** Hashed and random node ids live in a 16-bit space. With *n* generators, the chance that any two share a node id is about 1 − e^(−n²/131072): **0.07% at 10, 7% at 100, 50% at 300.** Two things reduce the risk:

- Even with a shared node id, two IDs only collide if both generators pick the same random starting sequence in the same millisecond (1 in 32,768).
- **For more than a few dozen instances, assign numeric node ids**, e.g. from a StatefulSet ordinal:

```ts
VID.initialize({ keys, currentKeyVersion: 1, nodeId: Number(process.env.HOSTNAME!.split("-").pop()) })
```

```yaml
# Kubernetes: expose the pod IP for auto-detection
env:
  - name: POD_IP
    valueFrom: { fieldRef: { fieldPath: status.podIP } }
```

---

## Security model

**Guarantees**

- The ID was produced by someone holding your secret.
- No byte has changed since it was generated.
- Each ID has exactly **one** valid string form, so string-keyed caches, dedupe and rate limits can't be bypassed with an alternate spelling.

**Not guaranteed (your app's job)**

- **Authorization.** A valid ID is not permission to read the resource.
- **Confidentiality.** Timestamp, node id and sequence are readable by anyone.
- **Replay and freshness.** Valid IDs stay valid until you revoke the key. Check `meta.timestamp` if you need expiry.

| Parameter | Value |
|---|---|
| MAC | HMAC-SHA256, truncated to 56 bits |
| Forgery odds | 1 in 7.2 × 10¹⁶ per guess; rate-limit endpoints that accept IDs |
| Key derivation | SHA-256(secret) → 32-byte key; the raw secret is never stored |
| Comparison | `crypto.timingSafeEqual` |

Found a vulnerability? Please report it privately; see [SECURITY.md](./SECURITY.md).

---

## FAQ

**Can I use VID as a primary key?**
Yes. Store it as `BYTEA` / `BinData` (18 bytes). Inserts are append-mostly, like UUIDv7.

**Does it work in browsers, Deno or Bun?**
It needs `node:crypto` and `node:worker_threads`. Bun and Deno implement both through their Node compatibility layers, but CI only covers Node.js today. Browsers and the Vercel/Cloudflare edge runtime aren't supported yet; see the roadmap.

**Should clients generate IDs?**
No. Only code that holds the secret can generate IDs, and that code is the trust boundary.

**Why 29 characters and not 26?**
18 bytes = 144 bits, and 144 ÷ 5 bits per base32 character rounds up to 29.

---

## Roadmap

- [ ] WebCrypto build for edge runtimes and browsers (verify-only)
- [ ] Optional sortable string encoding (Crockford base32) as a v2 format
- [ ] Go / Python verifiers for polyglot backends

Ideas and PRs are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[MIT](./LICENSE) © Kishan Kumar
