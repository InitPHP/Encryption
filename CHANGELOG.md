# Changelog

All notable changes to `initphp/encryption` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-11-22

### Changed

- **BREAKING:** Raised the minimum PHP version to 8.2 (`"php": "^8.2"`). The
  CI matrix now covers PHP 8.2, 8.3, 8.4 and 8.5.
- **BREAKING:** The code style moved to PER-CS, enforced by the shared
  PHP-CS-Fixer configuration (`.php-cs-fixer.dist.php`). The source was
  reformatted accordingly; there are no behaviour changes.

## [2.0.0] - 2026-05-24

The 2.x line is a deliberate hard reset of the public surface; ciphertexts
produced by 1.x cannot be decrypted by 2.x and vice versa. See
[`docs/Migration-from-1.x.md`](./docs/Migration-from-1.x.md) for the migration guide.

### Added

- Tooling: PHPUnit 10, PHPStan level 8, PHP-CS-Fixer (PSR-12), GitHub Actions CI
  matrix across PHP 8.1–8.4, `composer audit` workflow.
- `composer.json` scripts: `test`, `test-coverage`, `phpstan`, `cs-check`,
  `cs-fix`, `qa`.
- Package-level `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`.

### Changed (breaking)

- **BREAKING:** Minimum PHP version raised to `^8.1`.
- **BREAKING:** New self-describing ciphertext format (versioned header) — v1
  ciphertexts will not be readable by 2.x.
- **BREAKING:** Default payload serialization switches from `serialize()`/
  `unserialize()` to JSON. PHP serialization remains available as an opt-in.
- Sodium handler derives a 32-byte key from any-length user-supplied key
  material via `sodium_crypto_generichash`, fixing the silent failure when a
  short key was provided.
- OpenSSL handler uses `random_bytes()` for IV generation.
- OpenSSL handler computes the HMAC length from the actual hash output instead
  of parsing the algorithm name as a numeric suffix.
- Mandatory key validation with a descriptive `EncryptionException` instead of
  obscure `TypeError`s deep inside the extensions.
- Drop runtime dependency on `ext-mbstring`.
- PSR-12 compliance across the codebase.
- Removal of `Encrypt::create()` (alias of `Encrypt::use()`).

## [1.0.0] - 2022

Initial release.
