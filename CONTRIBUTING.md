# Contributing

Thanks for helping. Issues and PRs are welcome, and so is criticism of the design. If you think VID is the wrong tool for something, a [Discussion](https://github.com/KishanKumar08/veridjs/discussions) about why is a real contribution.

## Setup

```bash
git clone https://github.com/KishanKumar08/veridjs.git
cd veridjs
npm install
npm test        # builds, then runs node:test on tests/*.test.js
npm run bench   # throughput numbers on your machine
```

There are no runtime dependencies, and the goal is to keep it that way. `bson` is a dev dependency only for the Mongo adapter tests.

## Where to start

- Issues labelled [`good first issue`](https://github.com/KishanKumar08/veridjs/labels/good%20first%20issue) are small and self-contained, such as framework middleware, examples and CI.
- Issues labelled [`help wanted`](https://github.com/KishanKumar08/veridjs/labels/help%20wanted) are bigger, such as ports to other languages and runtimes.
- Comment on an issue before you start so two people don't build the same thing.

## Porting VID to another language or runtime

1. Read [SPEC.md](SPEC.md). It's the source of truth, not this package's source code.
2. Make your implementation pass every case in [`spec/test-vectors.json`](spec/test-vectors.json): `valid`, `accepted` and `invalid`.
3. Open an issue so it can be listed in the README.

A verifier alone is a useful port. Generation is optional.

## Guidelines

- **The binary format is a public contract.** Any change to the 18-byte layout, the base32 alphabet or the signature is a breaking change and needs an issue first. See [SPEC.md §11](SPEC.md#11-versioning).
- Add a test for every bug fix and every new behaviour.
- `verify()` and `verifyDetailed()` must never throw.
- Keep error messages actionable: say what was wrong and how to fix it.
- Update `CHANGELOG.md` under *Unreleased*.
- If you change `scripts/gen-test-vectors.js`, run `npm run vectors` and commit the regenerated `spec/test-vectors.json`. CI fails if they're out of sync.

## Security issues

Do not open public issues. See [SECURITY.md](SECURITY.md).
