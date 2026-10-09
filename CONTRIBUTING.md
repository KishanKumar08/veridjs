# Contributing

Thanks for helping. Issues and PRs are welcome.

## Setup

```bash
git clone https://github.com/KishanKumar08/veridjs.git
cd veridjs
npm install
npm test        # builds, then runs node:test on tests/*.test.js
npm run bench   # throughput numbers on your machine
```

There are no runtime dependencies, and the goal is to keep it that way. `bson` is a dev dependency only for the Mongo adapter tests.

## Guidelines

- **The binary format is a public contract.** Any change to the 18-byte layout, the base32 alphabet or the signature is a breaking change and needs an issue first.
- Add a test for every bug fix and every new behaviour.
- `verify()` and `verifyDetailed()` must never throw.
- Keep error messages actionable: say what was wrong and how to fix it.
- Update `CHANGELOG.md` under *Unreleased*.

## Security issues

Do not open public issues. See [SECURITY.md](SECURITY.md).
