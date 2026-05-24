# Contributing to `initphp/encryption`

This package follows the [InitPHP org-wide contribution guide](https://github.com/InitPHP/.github/blob/main/CONTRIBUTING.md).
Please read it first — everything below is in addition to that guide, not a
replacement for it.

## Local Development

```bash
git clone https://github.com/InitPHP/Encryption.git
cd Encryption
composer install
```

Required PHP extensions for the test suite:

- `ext-openssl`
- `ext-sodium`

## Quality Gates

The CI pipeline runs three checks. Run them locally before pushing — every PR
must pass all three.

| Command | What it does |
| --- | --- |
| `composer test` | Run the PHPUnit suite. |
| `composer phpstan` | Static analysis at level 8. |
| `composer cs-check` | Verify PSR-12 compliance (read-only). |
| `composer cs-fix` | Apply PSR-12 fixes automatically. |
| `composer qa` | Run cs-check, phpstan and tests in sequence. |

## Writing Tests

- Unit tests live in `tests/Unit/` and must not require any I/O or extension
  state beyond what `ext-openssl` and `ext-sodium` provide.
- Integration tests live in `tests/Integration/` and may pin golden
  ciphertexts for backwards-compatibility verification.
- A bug fix PR must include a regression test that fails on `main` and passes
  with the fix applied.
- Cover both the happy path and the failure paths (tampered ciphertext,
  invalid configuration, missing key, etc.).

## Security-Sensitive Changes

Any change that affects cryptographic primitives, key derivation, ciphertext
format, or the trust boundary between an attacker and the plaintext requires:

1. An explicit reviewer note in the PR description describing the threat model.
2. A test that exercises the failure path (e.g. tampered HMAC must be rejected).
3. A `CHANGELOG.md` entry under the appropriate section.

If you believe you have found a vulnerability, **do not open a public issue or
PR.** Follow the [security policy](./SECURITY.md) instead.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/). Typical
scopes for this repository:

- `openssl` — changes to `OpenSSL` handler
- `sodium` — changes to `Sodium` handler
- `base` — changes to `BaseHandler`
- `factory` — changes to `Encrypt`
- `docs`, `test`, `ci`, `chore` — as in the org guide

Example:

```
fix(openssl): handle openssl_decrypt failure before unserialize

openssl_decrypt() returns false on failure, which then caused
unserialize(false) to throw a TypeError on PHP 8.x. Detect the false
return and throw EncryptionException with a meaningful message.

Closes #NN
```
