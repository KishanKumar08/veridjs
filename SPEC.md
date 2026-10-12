# VID format specification

**Format version 1** · implemented by `@veridjs/core` ≥ 1.2.0

This document defines the VID binary layout, signature and string encoding precisely enough to write a compatible verifier or generator in any language. [`spec/test-vectors.json`](spec/test-vectors.json) contains test vectors. An implementation is compatible when it passes all of them.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

---

## 1. Binary layout

A VID is exactly **18 bytes**. All integers are **unsigned big-endian**.

| Offset | Size | Field | Range |
|---:|---:|---|---|
| 0 | 1 | `keyVersion` | 0–255 |
| 1 | 6 | `timestamp`: milliseconds since the Unix epoch, UTC | 0 – 2⁴⁸−1 |
| 7 | 2 | `nodeId` | 0–65535 |
| 9 | 2 | `sequence` | 0–65535 |
| 11 | 7 | `signature` | — |

Bytes 0–10 are the **payload**. Bytes 11–17 are the **signature**.

## 2. Keys

A deployment has a key ring that maps each `keyVersion` (0–255) to a secret string. Secrets MUST be at least 16 bytes when UTF-8 encoded. 32 or more random bytes are recommended.

The HMAC key is derived from the secret as follows:

```
key = SHA-256( UTF-8(secret) )          // 32 bytes
```

## 3. Signature

```
signature = first 7 bytes of HMAC-SHA256( key[keyVersion], payload )
```

The HMAC input is all 11 payload bytes, **including** the `keyVersion` byte. The key used is the one the payload's own `keyVersion` byte selects.

## 4. String encoding

The 18 bytes (144 bits) are encoded as **29 characters** using the RFC 4648 base32 alphabet without padding:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
```

Bits are taken most-significant first, 5 at a time. The last character carries the final 4 data bits followed by **1 padding bit, which MUST be 0**.

When decoding, a verifier:

- MUST trim leading and trailing whitespace
- MUST treat input as case-insensitive (lowercase is accepted)
- MUST reject strings that aren't exactly 29 characters after trimming
- MUST reject characters outside the alphabet
- MUST reject a final character whose padding bit is 1. Otherwise every ID would have two valid strings ("twins"), which breaks string-keyed caches, dedupe and rate limits

The canonical string form is uppercase with the padding bit set to 0. Generators MUST emit only canonical strings.

## 5. Verification

Given a string or 18-byte binary input, a verifier MUST:

1. Decode the string as described in §4. Binary input MUST be exactly 18 bytes.
2. Look up `keyVersion` (byte 0) in the key ring. If it's missing, the ID is invalid.
3. Compute the expected signature over bytes 0–10 as described in §3.
4. Compare it to bytes 11–17 **in constant time**.

Verification MUST NOT throw on malformed input. It returns valid or invalid.

The reference implementation reports these failure reasons from `verifyDetailed()`, and the test vectors use the same names:

| Reason | Meaning |
|---|---|
| `NULL_INPUT` | Input is null or undefined |
| `UNSUPPORTED_TYPE` | Input is not a string or binary |
| `INVALID_STRING_LENGTH` | Not 29 characters after trimming |
| `INVALID_STRING_CHARS` | Character outside the alphabet |
| `NON_CANONICAL_STRING` | Final padding bit is 1 |
| `INVALID_BINARY_LENGTH` | Binary is not 18 bytes |
| `UNKNOWN_KEY_VERSION` | `keyVersion` is not in the key ring |
| `SIGNATURE_MISMATCH` | Signature does not match |

Failure reasons SHOULD NOT be returned to untrusted clients, because they tell an attacker which check they got past. Log them internally instead.

## 6. Parsing

Parsing decodes the fields from a **verified** ID. Implementations SHOULD verify before parsing by default.

The reference implementation also rejects timestamps before **2020-01-01T00:00:00.000Z (1577836800000)** when parsing, because they can only come from corrupt data or a misconfigured clock. `verify()` checks only the signature.

## 7. Generation

Signature and encoding are what make IDs interoperable. Generation strategy affects uniqueness and ordering but not compatibility. The reference generator works like this:

- `timestamp` is the current time in milliseconds. If the clock moves backwards, the generator keeps using the last timestamp so IDs stay monotonic.
- `nodeId` MUST be unique among generators running at the same time. That includes each process and worker thread on a host. Two generators sharing a `nodeId` can produce identical IDs.
- `sequence` starts each millisecond at a **random value in [0, 32767]** and increments for each ID. If it would pass 65535, the generator waits for the next millisecond. This guarantees at least 32,768 IDs per millisecond per node. It also makes collisions between two generators that accidentally share a `nodeId` unlikely rather than certain.

## 8. Ordering

Sorting the **binary** form byte by byte orders IDs by `keyVersion`, then `timestamp`, then `nodeId`, then `sequence`. Within one key version this is chronological order, which keeps B-tree inserts mostly append-only.

The string form is **not** sortable in time order across key versions, because `keyVersion` is the first byte. Sort by the binary column.

## 9. Security properties and non-goals

- **What it gives you:** A verifier can tell whether an ID was produced by someone holding the key for its `keyVersion`, without any storage lookup. A random guess passes with probability 2⁻⁵⁶ per attempt. Rate-limit verification failures so online guessing stays impractical.
- **Not confidentiality:** All payload fields are readable by anyone who has the ID, including creation time and node.
- **Not authorization:** A valid ID proves where it came from, not that the caller may access the resource. Access checks are still required.
- **Not revocation:** Removing a key version invalidates every ID signed with it. Because IDs are usually stored permanently, old key versions normally stay in the ring for as long as their IDs exist. Rotating keys limits which **new** IDs a leaked key can forge. It does not invalidate old ones.
- **Not a MAC over context:** The signature covers only the payload. An ID valid in one place is valid everywhere that shares the key ring.

## 10. Test vectors

[`spec/test-vectors.json`](spec/test-vectors.json) has three sections:

- `valid`: fields, payload, signature, binary (hex) and canonical string. Implementations MUST produce the same bytes and string from the same fields and key, and MUST verify and parse them back to the same fields.
- `accepted`: non-canonical-looking inputs (lowercase, whitespace) that MUST verify and normalise to `canonical`.
- `invalid`: string (`input`) or binary (`inputHex`) inputs that MUST be rejected, with the expected `reason`.

The vectors are produced by [`scripts/gen-test-vectors.js`](scripts/gen-test-vectors.js). That script implements this spec independently and does not use the library.

### Worked example

Using the vector named `typical`:

```
secret      "vid-test-vector-secret-number-one"
key         SHA-256(secret)
            c10a068a928c2496888ace350f648576eb2c166aa9940ac1c6d1fb2d99858f97

keyVersion  1               → 01
timestamp   1791369154567   → 01a115ec1007   (2026-10-07T10:32:34.567Z)
nodeId      42              → 002a
sequence    1234            → 04d2

payload     0101a115ec1007002a04d2
signature   88f57b121d1c7f  (first 7 bytes of HMAC-SHA256(key, payload))
binary      0101a115ec1007002a04d288f57b121d1c7f
string      AEA2CFPMCADQAKQE2KEPK6YSDUOH6
```

## 11. Versioning

Any change to the layout, key derivation, signature input or truncation, or alphabet is a new **format version** and a major package release. Within format version 1, `keyVersion` identifies a key, not a format.
