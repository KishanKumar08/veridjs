# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.2.0] — Unreleased

### Security
- **Every ID now has exactly one valid string form.** The last base32 character carries one unused padding bit, and before 1.2.0 both values of that bit verified, so each ID had a second "twin" string. That breaks string-keyed caches, dedupe and rate limits. Non-canonical strings are now rejected with the reason `NON_CANONICAL_STRING`. IDs produced by `generate()` were always canonical, so stored IDs are unaffected.

### Fixed
- `VIDValue.fromString()` always threw (its pattern expected 26 characters instead of 29). This also broke `VIDPostgresAdapter.fromString/toCursor` and `VIDMongoAdapter.fromString`.
- `VIDValue` and the public types are exported from the package root, as the README already described.
- `VIDValue#parse()` and `VIDValue#equals()` exist, as the README already described.
- `VIDValue` now really copies the bytes it is built from.
- `VIDMongoAdapter.fromDatabase()` accepts `Binary` values from the mongodb driver's own copy of bson (it used `instanceof`, which fails across copies), and reads only the stored length of the buffer.
- Auto-detected node ids (from `POD_IP` / `HOSTNAME`) now include the process id and worker thread id. Before, cluster mode, PM2 and worker threads on one host all got the same node id and could generate duplicate IDs.
- LICENSE contains the full MIT text.

### Changed
- Each millisecond's sequence starts at a random value in `[0, 32767]`, so two generators that end up sharing a node id rarely collide. Capacity is still at least 32,768 IDs per millisecond per node.
- Generation is about 40% faster and verification about 10% faster. Keys are imported once at startup, config is validated once, and the signature is written directly into the output buffer.
- `exports` lists `types` conditions for every entry point.

### Added
- `VIDValue#toJSON()`, so `JSON.stringify({ id })` gives the string form.
- `VIDValue.compare(a, b)`, a comparator for sorting.
- A readable `util.inspect` / `console.log` form: `VIDValue(AEAZ…)`.
- A test suite with 54 tests, `npm run bench`, and CI on Node 18, 20, 22 and 24.

## [1.1.2]
- `./mongo` and `./postgres` exports point at the built files.
- `onWarning` option to route the random-nodeId warning through your logger.
