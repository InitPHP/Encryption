# Custom Handlers

`OpenSSL` and `Sodium` are deliberately `final` — they are end-points, not
extension points. If you need a different cryptographic primitive (a
KMS-wrapped key, hardware-backed AES, a different AEAD, …), build a new
handler on top of `BaseHandler`.

This page walks through a complete worked example.

## The Contract

`BaseHandler` does the boring parts for you: option resolution, key
validation, payload serialization and deserialization, format-version
constant. Your subclass only owns the cryptographic glue and the on-wire
layout between the format header and the ciphertext payload.

Implement two methods:

```php
abstract public function encrypt(mixed $data, array $options = []): string;
abstract public function decrypt(string $data, array $options = []): mixed;
```

…and follow three rules:

1. **Start every ciphertext with the 2-byte format header.**
   - Byte 0 = `BaseHandler::FORMAT_VERSION` (currently `0x02`)
   - Byte 1 = the serializer flag from `$this->serializerFlag($options)`
2. **Hex-encode the full wire payload** with `bin2hex()` on the way out and
   `hex2bin()` (or `@hex2bin()`) on the way in. The public surface is a
   hex string.
3. **Surface every failure as `EncryptionException`.** Wrap any underlying
   `SodiumException`, `OpenSSLException`, `JsonException`, etc.
   `EncryptionException` extends `\RuntimeException`, so callers only need
   one `catch`.

## A Worked Example: XChaCha20-Poly1305

Save this in your application namespace (not the package's):

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

        $key    = $this->deriveKey($userKey);
        $nonce  = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $header = chr(self::FORMAT_VERSION) . chr($flag);

        try {
            // The header is also the AEAD additional data, so any flip
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
        $nonce  = substr($binary, 2, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $box    = substr($binary, 2 + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

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

Use it through the factory just like the built-in handlers:

```php
use App\Crypto\XChaCha20Handler;
use InitPHP\Encryption\Encrypt;

$handler = Encrypt::use(XChaCha20Handler::class, ['key' => 'secret']);
$ct = $handler->encrypt(['user_id' => 42]);
$pt = $handler->decrypt($ct);
// $pt === ['user_id' => 42]
```

## What `BaseHandler` Gives You

These protected helpers are the contract. Use them rather than rolling your
own equivalents, so your handler picks up package-wide behaviour
automatically.

| Helper | Signature | Purpose |
| --- | --- | --- |
| `resolveOptions` | `(array $options): array` | Merge per-call options on top of persistent ones. Always returns a copy — safe to mutate or `sodium_memzero`. |
| `requireKey` | `(array $options): string` | Read `'key'`; throws `EncryptionException` if missing, empty, or not a string. |
| `serializerFlag` | `(array $options): int` | Resolve the configured serializer name (`'json'`, `'php_serialize'`, aliases…) to the wire flag byte. |
| `serializePayload` | `(mixed $data, int $flag): string` | Encode according to the flag. Throws on JSON-encode failure. |
| `unserializePayload` | `(string $data, int $flag): mixed` | Reverse `serializePayload`. PHP-serialised payloads use `allowed_classes: false`. |

Public option-management methods are inherited as-is: `setOption`,
`setOptions`, `getOption`, `getOptions`. Do not redeclare them.

## Adding Custom Option Keys

There is no declared schema. Just read what you need:

```php
$options = $this->resolveOptions($options);
$rotation = (int) ($options['rotation_id'] ?? 0);
```

`setOptions(array)` and `setOption(string, mixed)` accept arbitrary keys
(lowercased on the way in, so input is case-insensitive).

If you want IDE/PHPStan help on your custom keys, declare a typed property
or use a `@phpstan-type` alias.

## Versioning Your Own Format

The package reserves byte `0x02` for its own format. To evolve your custom
handler's layout without breaking deployed ciphertexts, **do not** overload
the package's version byte — instead, add your own version byte *inside*
your payload, between the format header and your data:

```text
+---------+-----------+----------------+--------------------+
| 0x02    | flag      | my-handler-ver | ... your bytes ... |
+---------+-----------+----------------+--------------------+
```

That way the package-level "is this a v2 ciphertext?" check still works,
and you have a private version byte you can bump independently.

## Testing Your Handler

The package's own test suite uses a `tests/Fixtures/DummyHandler.php` that
re-exposes `BaseHandler`'s protected helpers as public methods, so they
can be unit-tested without a real cryptographic primitive. You can use the
same pattern in your application.

At minimum, every custom handler should have tests for:

- A round-trip across the data types your callers will pass.
- Tampered ciphertext is rejected.
- A ciphertext with the wrong version byte is rejected.
- A missing or empty `key` raises `EncryptionException`.
- Per-call options do **not** mutate handler state (no leaked option writes).

See [Testing Your Encryption](Testing-Your-Encryption.md) for a worked test
pattern.

## See Also

- [OpenSSL Handler](OpenSSL-Handler.md) — reference implementation with
  HKDF + HMAC.
- [Sodium Handler](Sodium-Handler.md) — reference implementation with
  secretbox.
- [Configuration Options](Configuration-Options.md) — every built-in option.
- [Security Best Practices](Security-Best-Practices.md) — what the package
  considers in-scope vs out-of-scope.
