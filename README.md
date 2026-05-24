# initphp/encryption

Secure, modern symmetric encryption for PHP on top of OpenSSL and libsodium.

[![Latest Stable Version](https://poser.pugx.org/initphp/encryption/v)](https://packagist.org/packages/initphp/encryption)
[![Total Downloads](https://poser.pugx.org/initphp/encryption/downloads)](https://packagist.org/packages/initphp/encryption)
[![License](https://poser.pugx.org/initphp/encryption/license)](https://packagist.org/packages/initphp/encryption)
[![PHP Version Require](https://poser.pugx.org/initphp/encryption/require/php)](https://packagist.org/packages/initphp/encryption)

## Why

PHP's encryption primitives are powerful but unforgiving. Pick the wrong cipher,
mix up IV and HMAC ordering, forget constant-time comparison, or hand libsodium
a 14-byte "key" and you ship a vulnerability — or, more often, a silent failure
that "works on my machine".

This package wraps `ext-openssl` and `ext-sodium` behind a small, opinionated
API:

- Authenticated by default. OpenSSL uses encrypt-then-MAC; Sodium uses the
  built-in AEAD construction.
- Keys of any non-empty length are accepted and derived to the size the
  primitive actually requires.
- Ciphertexts are self-describing: a 2-byte header (version + serializer flag)
  lets the library reject malformed or out-of-date input with a clear error
  instead of returning garbage.
- A single `EncryptionException` covers every failure mode, so a `try` /
  `catch` is enough to handle all error paths.
- JSON is the default payload serializer, so the historical
  `unserialize()`-on-attacker-controlled-bytes pitfall is closed by default.

## Requirements

- PHP **8.1** or higher
- `ext-openssl` for the OpenSSL handler
- `ext-sodium` for the Sodium handler

Both extensions ship with mainstream PHP distributions, but the package only
loads the one you actually instantiate — you can use one handler without the
other being available.

## Installation

```bash
composer require initphp/encryption
```

## Quickstart

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\OpenSSL;

$handler = Encrypt::use(OpenSSL::class, [
    'key' => getenv('APP_ENCRYPTION_KEY'),
]);

$ciphertext = $handler->encrypt(['user_id' => 42, 'role' => 'admin']);
// → "02006f1c…": hex string, safe to store in cookies / DBs / URL params

$plaintext = $handler->decrypt($ciphertext);
// → ['user_id' => 42, 'role' => 'admin']
```

The Sodium handler has the same surface:

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, [
    'key' => getenv('APP_ENCRYPTION_KEY'),
]);

$ciphertext = $handler->encrypt('a secret message');
$plaintext  = $handler->decrypt($ciphertext);
```

## Configuration

Every option is optional except `key`. Unknown keys are ignored. Keys are
case-insensitive on input (`'CIPHER'` and `'cipher'` are the same option).

| Option       | Used by   | Default        | Description |
| ------------ | --------- | -------------- | ----------- |
| `key`        | both      | _required_     | The user-supplied secret. Any non-empty string; the handler derives a key of the correct length internally. |
| `cipher`     | OpenSSL   | `AES-256-CTR`  | Any algorithm from `openssl_get_cipher_methods()`. |
| `algo`       | OpenSSL   | `SHA256`       | Any algorithm from `hash_hmac_algos()`. Used both for HKDF key derivation and for the HMAC tag. |
| `blocksize`  | Sodium    | `16`           | Block size for `sodium_pad()` / `sodium_unpad()`. Must be a positive integer. |
| `serializer` | both      | `'json'`       | One of `'json'`, `'php_serialize'`, `'php'`, `'serialize'`. See [Serialization](#serialization). |

Options can be set in three places, in order of precedence (highest wins):

```php
// 1) Per-call override
$handler->encrypt($data, ['cipher' => 'AES-256-GCM']);

// 2) Mutated on the handler
$handler->setOption('cipher', 'AES-256-GCM');
$handler->setOptions(['cipher' => 'AES-256-GCM', 'algo' => 'SHA512']);

// 3) Constructor / factory
$handler = Encrypt::use(OpenSSL::class, ['cipher' => 'AES-256-GCM']);
```

Per-call options do **not** mutate the handler — they are merged into a fresh
array for that single call only.

## Serialization

`encrypt()` accepts `mixed` and round-trips the value through a serializer
chosen via the `serializer` option. The flag is embedded in the ciphertext, so
`decrypt()` always restores the original type without you having to track the
choice yourself.

| `serializer` value | On-the-wire flag | Behaviour |
| --- | --- | --- |
| `'json'` (default) | `0x00` | Uses `json_encode`/`json_decode` with `JSON_THROW_ON_ERROR`. Safe: no PHP class is ever instantiated during decoding. Cannot carry raw binary bytes — use `php_serialize` if you need that. |
| `'php_serialize'`, `'php'`, `'serialize'` | `0x01` | Uses `serialize()`/`unserialize()` with `['allowed_classes' => false]`. Round-trips scalars, arrays and binary strings; custom objects degrade to `__PHP_Incomplete_Class` on decode. |

The PHP serializer is opt-in for one reason only: even though we always pass
`allowed_classes:false`, the safer default lets you not have to think about
object-injection vectors at all.

## Writing a Custom Handler

Extend `BaseHandler` (not `OpenSSL` / `Sodium` — those are `final`) and
implement `encrypt()` and `decrypt()`:

```php
namespace App\Crypto;

use InitPHP\Encryption\BaseHandler;
use InitPHP\Encryption\Exceptions\EncryptionException;

final class MyHandler extends BaseHandler
{
    public function encrypt(mixed $data, array $options = []): string
    {
        $options       = $this->resolveOptions($options);
        $key           = $this->requireKey($options);
        $serializerFlag = $this->serializerFlag($options);

        $payload = $this->serializePayload($data, $serializerFlag);
        // ... apply your primitive of choice, return a hex-encoded string ...
    }

    public function decrypt(string $data, array $options = []): mixed
    {
        $options       = $this->resolveOptions($options);
        $key           = $this->requireKey($options);

        // ... reverse the encoding, return $this->unserializePayload($plain, $flag) ...
    }
}

// Use it via the factory just like the built-in handlers:
$handler = \InitPHP\Encryption\Encrypt::use(\App\Crypto\MyHandler::class, [
    'key' => 'secret',
]);
```

`BaseHandler` gives you `resolveOptions()`, `requireKey()`,
`serializerFlag()`, `serializePayload()` and `unserializePayload()` for free,
so you only write the cryptographic glue.

## Error Handling

Every failure path raises `InitPHP\Encryption\Exceptions\EncryptionException`
(which extends `\RuntimeException`). A single `catch` covers everything:

```php
use InitPHP\Encryption\Exceptions\EncryptionException;

try {
    $plaintext = $handler->decrypt($incoming);
} catch (EncryptionException $e) {
    // Bad input, tampered ciphertext, missing key, unsupported format
    // version, unknown cipher or hash algorithm, …
    $logger->warning('decrypt failed', ['reason' => $e->getMessage()]);
}
```

Notable messages you may see:

- `Unsupported ciphertext format version 0x01; expected 0x02. Ciphertexts produced by 1.x are not readable by 2.x.`
- `HMAC verification failed; ciphertext is corrupted or has been tampered with.`
- `Sodium decryption failed; ciphertext is corrupted or has been tampered with.`
- `The "key" option is required and must be a non-empty string.`
- `Unknown OpenSSL cipher "…".`

## Security Notes

- **Key management is your job.** Store the key outside the code repository —
  environment variable, secret manager, KMS, etc. — and rotate it like any
  other secret.
- **Key strength matters.** The handler accepts any non-empty user key and
  derives one of the right length, but it cannot add entropy that the input
  does not contain. Use a random 256-bit string (`bin2hex(random_bytes(32))`)
  in production rather than a passphrase.
- **Authentication is always on.** OpenSSL ciphertexts include an HMAC of the
  header, IV, and ciphertext; Sodium uses its built-in AEAD. There is no
  "encrypt without authenticate" mode.
- **Format is versioned.** The first byte of every ciphertext identifies the
  format. A future major release that changes the layout will bump this byte
  and reject older ciphertexts with a clear error.
- **Found something concerning?** See [SECURITY.md](./SECURITY.md) — please do
  not open a public issue for vulnerabilities.

## Upgrading from 1.x

Version 2.0 is a hard reset of the public surface and the on-wire format:

- Minimum PHP version is now **8.1**.
- Ciphertexts produced by 1.x **cannot be decrypted by 2.x.** Plan a
  re-encryption migration before upgrading.
- The default payload serializer is JSON (was `serialize`). Pass
  `'serializer' => 'php_serialize'` to keep the old behaviour.
- `Encrypt::create()` has been removed; use `Encrypt::use()`.
- The Sodium handler no longer requires a 32-byte key — any non-empty string
  is now accepted and derived internally.
- `ext-mbstring` is no longer required.

A full migration walk-through lives in
[`docs/08-migration-v1-to-v2.md`](./docs/08-migration-v1-to-v2.md) (shipped
with the package; see also the [docs/](./docs/) index).

## Contributing

PRs are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first — it
covers the local quality gates (`composer test`, `composer phpstan`,
`composer cs-check`) and the security-review process for changes touching the
cryptographic primitives.

## License

MIT — see [LICENSE](./LICENSE).
