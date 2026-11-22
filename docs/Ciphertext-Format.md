# Ciphertext Format

Every ciphertext produced by an `initphp/encryption` 2.x handler is a
**hex-encoded** string that decodes to a binary payload with a
**self-describing 2-byte header**. This page is the wire format reference.

## Why a Versioned Format?

In 1.x, the wire format was the raw concatenation of HMAC + IV + ciphertext
(OpenSSL) or nonce + box (Sodium). It worked, but it had two problems:

1. **Silent breakage when the format evolves.** Changing the layout would
   make the new code silently corrupt old ciphertexts.
2. **No way to refuse stale input.** A 2.x library has no way to detect
   "this came from 1.x" — it would just hit a MAC failure deep in the
   pipeline and surface an opaque error.

2.x solves both: the first byte of every ciphertext is `0x02`. Any handler
that sees a different first byte rejects the input immediately with a
clear message:

```
Unsupported ciphertext format version 0x01; expected 0x02. Ciphertexts
produced by 1.x are not readable by 2.x.
```

A future major release that changes the layout will bump this byte to
`0x03` and reject `0x02` input the same way.

## The Format Header

The first two bytes of every binary payload (after `hex2bin`) are:

| Offset | Size | Name | Values |
| ---: | ---: | --- | --- |
| `0` | 1 byte | **VERSION** | `0x02` |
| `1` | 1 byte | **SERIALIZER** | `0x00` (JSON), `0x01` (`php_serialize`) |

Constants exposed by the package:

```php
\InitPHP\Encryption\BaseHandler::FORMAT_VERSION;   // 0x02 (int 2)
\InitPHP\Encryption\BaseHandler::SERIALIZER_JSON;  // 'json'
\InitPHP\Encryption\BaseHandler::SERIALIZER_PHP;   // 'php_serialize'
```

The internal flag bytes (`0x00` / `0x01`) are an implementation detail and
not surfaced as public constants — use the named string constants when
configuring the `serializer` option.

## OpenSSL Layout

```
+---------+-----------+---------+---------+----------------+
| 1 byte  | 1 byte    | N bytes | M bytes | variable       |
+---------+-----------+---------+---------+----------------+
| VERSION | SERIALIZER| HMAC    | IV      | ciphertext     |
+---------+-----------+---------+---------+----------------+
```

- `N` = `strlen(hash_hmac($algo, '', '', true))` — 32 for SHA-256, 64 for
  SHA-512, etc.
- `M` = `openssl_cipher_iv_length($cipher)` — usually 16 for AES, 0 for
  ciphers with no IV.
- The HMAC authenticates `VERSION || SERIALIZER || IV || ciphertext` —
  flipping the serializer byte invalidates the MAC.

Decryption computes the HMAC over the same byte range and compares with
`hash_equals()` (constant-time).

## Sodium Layout

```
+---------+-----------+----------+----------------------+
| 1 byte  | 1 byte    | 24 bytes | variable             |
+---------+-----------+----------+----------------------+
| VERSION | SERIALIZER| NONCE    | secretbox(MAC || CT) |
+---------+-----------+----------+----------------------+
```

- The 24-byte nonce is `SODIUM_CRYPTO_SECRETBOX_NONCEBYTES`. Generated
  per-call via `random_bytes()`.
- `secretbox(MAC || CT)` is the libsodium output: Poly1305 MAC prepended
  to the ciphertext, total length = padded plaintext +
  `SODIUM_CRYPTO_SECRETBOX_MACBYTES` (16).

There is no separate HMAC field — Poly1305 authenticates `MAC || CT`
implicitly inside the secretbox construction.

## Cross-Handler Decryption Is Rejected

Both handlers honour the same 2-byte header, but the bytes after the
header are not interchangeable. Decrypting an OpenSSL ciphertext with the
Sodium handler (or vice versa) will fail at the MAC check:

```php
use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Sodium;
use InitPHP\Encryption\Exceptions\EncryptionException;

$openssl = new OpenSSL(['key' => 'k']);
$sodium  = new Sodium(['key' => 'k']);

$ct = $sodium->encrypt(['payload' => 'cross']);

try {
    $openssl->decrypt($ct); // wrong handler
} catch (EncryptionException $e) {
    echo $e->getMessage(), PHP_EOL;
    // → HMAC verification failed; ciphertext is corrupted or has been tampered with.
}
```

The package's integration test suite asserts this in both directions.

## Inspecting a Ciphertext By Hand

You can decode the header yourself for debugging without instantiating a
handler:

```php
$ciphertext = '02006f1cabc...';
$binary     = hex2bin($ciphertext);

$version    = ord($binary[0]); // 0x02 (=> 2)
$serializer = ord($binary[1]); // 0x00 (JSON) or 0x01 (php_serialize)

printf("version=0x%02x serializer=0x%02x bytes=%d\n",
    $version, $serializer, strlen($binary)
);
```

Useful when triaging "this ciphertext won't decrypt" tickets in
production logs.

## Forward Compatibility

When a future 3.x release introduces a new layout, the version byte will
become `0x03`. Code that opens an old ciphertext under a 3.x handler will
see:

```
Unsupported ciphertext format version 0x02; expected 0x03.
```

Migration guides (when needed) will live in the
[Migration from 1.x](Migration-from-1.x.md) family of pages. There are no
plans for a 3.x format change in the foreseeable future.

## See Also

- [OpenSSL Handler](OpenSSL-Handler.md) — how each field is filled in for
  OpenSSL.
- [Sodium Handler](Sodium-Handler.md) — how each field is filled in for
  Sodium.
- [Serialization](Serialization.md) — what the serializer flag means.
- [Migration from 1.x](Migration-from-1.x.md) — what the version-byte rejection
  looks like for callers upgrading from 1.x.
