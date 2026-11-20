# Security Policy

`initphp/encryption` ships cryptographic primitives, so a vulnerability here
typically affects every downstream user. Please report responsibly.

This package follows the [InitPHP org-wide security policy](https://github.com/InitPHP/.github/blob/main/SECURITY.md).
Refer to that document for:

- How to report a vulnerability (GitHub Private Vulnerability Reporting is
  preferred; email is accepted).
- The response timeline and disclosure process.
- Which versions receive security updates.

## Quick Reference

- **Do not** open public issues, Discussions, or PRs for security
  vulnerabilities.
- **Preferred channel:** GitHub Private Vulnerability Reporting on this
  repository's **Security** tab.
- **Alternative channel:** Email
  [info@muhammetsafak.com](mailto:info@muhammetsafak.com) with `SECURITY`
  in the subject line.

## Supported Versions

| Version | Status |
| --- | --- |
| 2.x | ✅ Active — security fixes land here. |
| 1.x | ❌ End-of-life on the day 2.0.0 ships. Please upgrade. |

When in doubt, run `composer show initphp/encryption` to confirm your version
and `composer outdated initphp/encryption` to see if an upgrade is available.

## Scope Notes Specific to This Package

The following are **in scope** for this package's security policy:

- Cryptographic correctness of the OpenSSL and Sodium handlers (padding,
  authentication, IV/nonce reuse, key derivation).
- Side-channel issues in the verification paths (timing, error oracles).
- Deserialization or injection issues in the public encrypt/decrypt API.
- Documentation that materially understates a known cryptographic limitation.

The following are **out of scope**:

- Misuse of the API by application code (e.g. shipping the secret key in
  client-visible storage). Documentation PRs that help others avoid such
  pitfalls are welcome.
- Vulnerabilities in PHP itself, `ext-openssl`, or `libsodium` — report those
  upstream.
- Brute-force attacks against weak user-supplied keys. The package will derive
  a key of the correct length from any input, but it cannot add entropy that
  the input does not contain.
