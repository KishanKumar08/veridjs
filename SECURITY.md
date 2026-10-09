# Security Policy

## Supported versions

| Version | Supported |
|---|:---:|
| 1.2.x | ✅ |
| < 1.2 | ❌ — upgrade; 1.2.0 fixes a string-malleability issue (see CHANGELOG) |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Report privately through either channel:

- GitHub: **Security → Report a vulnerability** on [KishanKumar08/veridjs](https://github.com/KishanKumar08/veridjs/security/advisories/new)
- Email: **kmali4551@gmail.com**

Include the version, a minimal reproduction, and the impact you expect. You will get an acknowledgement within 48 hours and a timeline for a fix. Credit is given in the release notes unless you ask otherwise.

## Security model, in short

- VID proves an ID was **issued by a holder of your secret** and was **not modified**. It does not encrypt anything: timestamp, node id and sequence are readable by anyone.
- The signature is HMAC-SHA256 truncated to 56 bits. Online forgery needs ~2⁵⁵ guesses on average; rate-limit endpoints that accept IDs.
- Anyone with the secret can mint valid IDs. Keep secrets in a secrets manager and rotate with `keys` + `currentKeyVersion`.
- A valid VID is not an authorization check. Still confirm the caller may access the resource.
