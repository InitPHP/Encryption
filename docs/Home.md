# InitPHP Encryption — Documentation

Welcome to the official documentation for **`initphp/encryption`** — a small,
opinionated symmetric encryption library for PHP 8.2+ built on `ext-openssl`
and `ext-sodium`.

The package wraps PHP's two production-grade cryptographic extensions behind
a single, hard-to-misuse API. Pick a handler, pass a key, encrypt anything —
the library handles key derivation, authentication, format versioning and
safe serialization for you.

```bash
composer require initphp/encryption
```

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, ['key' => getenv('APP_KEY')]);

$ciphertext = $handler->encrypt(['user_id' => 42, 'role' => 'admin']);
// → "020047ae3f8c..." — hex, safe for cookies / DBs / URLs

$payload = $handler->decrypt($ciphertext);
// → ['user_id' => 42, 'role' => 'admin']
```

The package ships two handlers and one extension point:

| Class | Purpose |
| --- | --- |
| [`OpenSSL`](OpenSSL-Handler.md) | AES-family ciphers with HMAC authentication; configurable cipher and hash. |
| [`Sodium`](Sodium-Handler.md) | libsodium's XSalsa20-Poly1305 AEAD; no tunables to get wrong. |
| [`BaseHandler`](Custom-Handlers.md) | Abstract base for building your own handler around any primitive. |

Both built-in handlers implement the same `HandlerInterface`, so swapping
between them is a constructor change.

## Start Here

- **New to the package?** Read [Installation](Installation.md), then
  [Quick Start](Quick-Start.md).
- **Picking a handler?** Compare [OpenSSL](OpenSSL-Handler.md) and
  [Sodium](Sodium-Handler.md) side by side.
- **Writing your own handler?** See [Custom Handlers](Custom-Handlers.md).
- **Coming from 1.x?** Start with [Migration from 1.x](Migration-from-1.x.md) —
  ciphertexts produced by 1.x are not readable by 2.x.
- **Looking for a specific method?** The full [API Reference](API-Reference.md)
  lists every public class member.

## Navigation

### Getting Started
- [Installation](Installation.md)
- [Quick Start](Quick-Start.md)

### Handlers
- [OpenSSL Handler](OpenSSL-Handler.md)
- [Sodium Handler](Sodium-Handler.md)
- [Custom Handlers](Custom-Handlers.md)

### Reference
- [Configuration Options](Configuration-Options.md)
- [Ciphertext Format](Ciphertext-Format.md)
- [Serialization](Serialization.md)
- [Error Handling](Error-Handling.md)
- [API Reference](API-Reference.md)

### Practical Guides
- [Recipes](Recipes.md)
- [Security Best Practices](Security-Best-Practices.md)
- [Testing Your Encryption](Testing-Your-Encryption.md)
- [Troubleshooting](Troubleshooting.md)

### Other
- [Migration from 1.x](Migration-from-1.x.md)
- [FAQ](FAQ.md)

## At a Glance — Handler Comparison

| Capability | `OpenSSL` | `Sodium` |
| --- | :---: | :---: |
| Authenticated encryption | ✅ (HMAC, encrypt-then-MAC) | ✅ (Poly1305 AEAD) |
| Random IV / nonce per call | ✅ (`random_bytes`) | ✅ (`random_bytes`) |
| Accepts any-length user key | ✅ (HKDF) | ✅ (BLAKE2b) |
| Configurable cipher | ✅ | — |
| Configurable hash | ✅ | — |
| Length-hiding padding | — | ✅ (`sodium_pad`) |
| Self-describing format header | ✅ (version + serializer flag) | ✅ (version + serializer flag) |
| JSON serializer (default) | ✅ | ✅ |
| PHP serializer (opt-in, safe) | ✅ | ✅ |
| Single exception class for all errors | ✅ | ✅ |

If you have no opinion, **use the Sodium handler.** It is harder to misuse,
and the defaults are correct.

## What You Get

- **Authenticated by default.** No "encrypt without authenticate" mode —
  tampered ciphertexts always raise an exception, never decrypt to garbage.
- **Versioned wire format.** Every ciphertext begins with a magic byte
  (`0x02`); future format changes will bump it and reject older ciphertexts
  with a clear error instead of silent corruption.
- **One exception type.** Every failure raises
  `InitPHP\Encryption\Exceptions\EncryptionException`. One `catch` covers
  everything — see [Error Handling](Error-Handling.md).
- **Safe-by-default serialization.** JSON is the default, so the historical
  `unserialize()`-on-attacker-bytes pitfall is closed without you having to
  think about it. PHP serialize stays available as an opt-in for binary
  payloads, with `allowed_classes: false` always set.
- **Free key flexibility.** Pass any non-empty string for `key`; the handler
  derives a key of the correct length internally.

## Conventions in This Documentation

- "Ciphertext" always means the hex string returned by `encrypt()`. The
  underlying bytes are described as "binary".
- The 2-byte header on every ciphertext is the *format header*; byte 0 is the
  *version byte* (`0x02` in this release), byte 1 is the *serializer flag*
  (`0x00` = JSON, `0x01` = `php_serialize`). See [Ciphertext Format](Ciphertext-Format.md).
- "User key" is whatever string you pass in the `key` option. "Derived key" is
  what the handler feeds to the cryptographic primitive after key derivation
  (HKDF for OpenSSL, BLAKE2b for Sodium).

## Package Metadata

- **License**: MIT
- **Minimum PHP**: 8.2
- **Required extensions** (per handler): `ext-openssl` *or* `ext-sodium`
- **Packagist**: [`initphp/encryption`](https://packagist.org/packages/initphp/encryption)
- **Source**: [github.com/InitPHP/Encryption](https://github.com/InitPHP/Encryption)
- **Issues**: [github.com/InitPHP/Encryption/issues](https://github.com/InitPHP/Encryption/issues)
- **Discussions**: [github.com/orgs/InitPHP/discussions](https://github.com/orgs/InitPHP/discussions)
- **Security**: [`SECURITY.md`](https://github.com/InitPHP/.github/blob/main/SECURITY.md) —
  please **do not** open a public issue for vulnerabilities.

If something in this documentation is unclear, wrong, or out of date,
[open an issue](https://github.com/InitPHP/Encryption/issues/new) — doc
fixes are merged eagerly.
