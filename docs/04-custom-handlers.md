# Writing a Custom Handler

`OpenSSL` and `Sodium` are deliberately `final` — they are end-points, not
extension points. If you need a different cryptographic primitive (a key
wrapped by a KMS, a different AEAD, a hardware-backed cipher), build a new
handler on top of `BaseHandler`.

This page walks through a complete worked example. The handler we build
wraps libsodium's `crypto_aead_xchacha20poly1305_ietf_*` family, which gives
you a 24-byte nonce (large enough to be safely random) and a single
authenticated-encryption call.

## The Contract You Must Honour

`BaseHandler` does the boring parts for you: option resolution, key
validation, payload serialization and deserialization, the format-version
constant. Your subclass only owns the cryptographic glue and the on-wire
layout between the format header and the ciphertext payload.

Implement two methods:

```php
abstract public function encrypt(mixed $data, array $options = []): string;
abstract public function decrypt(string $data, array $options = []): mixed;
```

…and follow three rules:

1. **Start every ciphertext with the format header.** Two bytes:
   - byte 0 = `BaseHandler::FORMAT_VERSION` (currently `0x02`)
   - byte 1 = the serializer flag returned by `$this->serializerFlag($options)`
2. **Hex-encode the entire wire payload** with `bin2hex()` on the way out,
   and `hex2bin()` (or `@hex2bin()`) on the way in. The public surface is a
   hex string.
3. **Surface every failure as `EncryptionException`.** Wrap any underlying
   exception (`SodiumException`, `OpenSSLException`, `JsonException`, ...)
   so callers only need one `catch`.

## A Full Example

Save this as `src/XChaCha20Handler.php` (in your application namespace, not
the package's):

```php
<?php

declare(strict_types=1);

namespace App\Crypto;

use InitPHP\Encryption\BaseHandler;
use InitPHP\Encryption\Exceptions\EncryptionException;
use SodiumException;

final class XChaCha20Handler extends BaseHandler
{
    public function __construct(array $options = [])
    {
        if (!extension_loaded('sodium')) {
            throw new EncryptionException('The "sodium" extension is required.');
        }
        parent::__construct($options);
    }

    public function encrypt(mixed $data, array $options = []): string
    {
        $options = $this->resolveOptions($options);
        $userKey = $this->requireKey($options);
        $flag    = $this->serializerFlag($options);

        $payload = $this->serializePayload($data, $flag);

        $key   = $this->deriveKey($userKey);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $header = chr(self::FORMAT_VERSION) . chr($flag);

        try {
            // header is also the AEAD's additional data, so any flip
            // to the version / serializer byte invalidates the MAC.
            $box = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $payload,
                $header,
                $nonce,
                $key,
            );
        } finally {
            sodium_memzero($key);
        }

        return bin2hex($header . $nonce . $box);
    }

    public function decrypt(string $data, array $options = []): mixed
    {
        $options = $this->resolveOptions($options);
        $userKey = $this->requireKey($options);

        $binary = @hex2bin($data);
        if ($binary === false) {
            throw new EncryptionException('Ciphertext is not valid hex-encoded data.');
        }

        $minLength = 2
            + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if (strlen($binary) < $minLength) {
            throw new EncryptionException('Ciphertext is too short.');
        }

        $version = ord($binary[0]);
        if ($version !== self::FORMAT_VERSION) {
            throw new EncryptionException(
                sprintf('Unsupported ciphertext format version 0x%02x.', $version),
            );
        }
        $flag   = ord($binary[1]);
        $header = substr($binary, 0, 2);

        $nonce = substr($binary, 2, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $box   = substr($binary, 2 + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $key = $this->deriveKey($userKey);
        try {
            $payload = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $box,
                $header,
                $nonce,
                $key,
            );
        } catch (SodiumException $e) {
            throw new EncryptionException('XChaCha20 decryption failed.', 0, $e);
        } finally {
            sodium_memzero($key);
        }

        if ($payload === false) {
            throw new EncryptionException(
                'XChaCha20 decryption failed; ciphertext is corrupted or has been tampered with.',
            );
        }

        return $this->unserializePayload($payload, $flag);
    }

    private function deriveKey(string $userKey): string
    {
        return sodium_crypto_generichash(
            $userKey,
            '',
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
        );
    }
}
```

Use it the same way as the built-in handlers:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use App\Crypto\XChaCha20Handler;
use InitPHP\Encryption\Encrypt;

$handler = Encrypt::use(XChaCha20Handler::class, ['key' => 'secret']);
$ct = $handler->encrypt(['user_id' => 42]);
$pt = $handler->decrypt($ct);

assert($pt === ['user_id' => 42]);
```

## What `BaseHandler` Gives You

These protected helpers are the contract — use them rather than rolling your
own equivalents, so your handler picks up package-wide behaviour
automatically.

| Helper | What it does |
| --- | --- |
| `resolveOptions(array $options): array` | Merges per-call options on top of persistent ones; always returns a copy. Use this at the top of `encrypt()` / `decrypt()`. |
| `requireKey(array $options): string` | Reads `'key'`; throws `EncryptionException` if missing, empty, or not a string. |
| `serializerFlag(array $options): int` | Resolves the configured serializer name (`'json'`, `'php_serialize'`, aliases…) to the on-wire flag byte. |
| `serializePayload(mixed $data, int $flag): string` | Encodes a payload according to the flag. Throws on JSON-encode failure. |
| `unserializePayload(string $data, int $flag): mixed` | Reverses `serializePayload`; PHP-serialized payloads use `allowed_classes: false`. |

Public option-management methods are inherited as-is: `setOption`,
`setOptions`, `getOption`, `getOptions`. You do not need to redeclare them.

## Adding Custom Option Keys

If your handler needs configuration beyond what `BaseHandler` provides, just
read it out of the resolved options:

```php
$options = $this->resolveOptions($options);
$rotation = (int) ($options['rotation_id'] ?? 0);
```

`setOption(string, mixed)` and `setOptions(array)` already accept arbitrary
keys (they are lowercased on the way in, so input is case-insensitive).
There is no need to declare a property — just read what you need.

If you want IDE/PHPStan help on your custom keys, declare a typed property
or use a `@phpstan-type` alias.

## Versioning Your Own Format

The package reserves `0x02` for its own format. If you want to evolve your
custom handler's layout without breaking deployed ciphertexts, do **not**
overload the package's version byte — instead, add your own version byte
*inside* your payload, between the format header and your data:

```text
+---------+-----------+----------------+--------------------+
| 0x02    | flag      | my-handler-ver | ... your bytes ... |
+---------+-----------+----------------+--------------------+
```

That way the package-level "is this a v2 ciphertext?" check still works, and
you have a private version byte you can bump independently.

## Testing Your Handler

The package's own test suite extends `BaseHandler` via
`tests/Fixtures/DummyHandler.php` to exercise the protected helpers without
needing a real cryptographic primitive. You can do the same in your own
project; or, if your handler hits a real extension, write tests modelled on
`tests/Unit/OpenSSLTest.php` and `tests/Unit/SodiumTest.php` and run them
under PHPUnit.

At minimum, every custom handler should have tests for:

- A round-trip across the data types your callers will pass.
- Tampered ciphertext is rejected.
- A ciphertext with the wrong version byte is rejected.
- A missing or empty `key` raises `EncryptionException`.
- Per-call options do not mutate handler state (no leaked option writes).

## See Also

- [02 — OpenSSL Handler](./02-openssl-handler.md) — reference implementation
  with HKDF + HMAC.
- [03 — Sodium Handler](./03-sodium-handler.md) — reference implementation
  with secretbox.
- [07 — Security](./07-security.md) — what the package as a whole considers
  in-scope vs out-of-scope.
