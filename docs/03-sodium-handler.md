# Sodium Handler

`InitPHP\Encryption\Sodium` wraps libsodium's `crypto_secretbox` AEAD
construction (XSalsa20-Poly1305). It is the recommended default: the
underlying primitive has no tunables, the API is hard to misuse, and
authentication is part of the construction rather than something you bolt on
afterwards.

## What the Handler Does Per Call

```text
encrypt($data, $options)
    1. resolve options (per-call options merged on top of handler defaults)
    2. require a non-empty 'key' option
    3. read 'blocksize' (default 16) and validate it is a positive integer
    4. derive a 32-byte secretbox key from the user key:
       sodium_crypto_generichash($userKey, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES)
    5. serialize $data via the configured serializer (default: JSON)
    6. sodium_pad($serialized, $blocksize)
    7. generate a fresh 24-byte nonce: random_bytes(...)
    8. sodium_crypto_secretbox($padded, $nonce, $derivedKey) → box bytes
    9. zero the derived key from memory
   10. return bin2hex(VERSION || SERIALIZER || NONCE || BOX)

decrypt($data, $options)
    1. resolve options, require key, resolve blocksize (same as above)
    2. hex2bin → binary
    3. reject if shorter than 2 + nonce + MAC bytes
    4. read the 2-byte header; reject if version byte ≠ 0x02
    5. read the 24-byte nonce
    6. re-derive the same secretbox key from the user key
    7. sodium_crypto_secretbox_open(...) — fails if the MAC doesn't match
    8. sodium_unpad(...) → original serialized bytes
    9. zero the derived key from memory
   10. deserialize per the serializer flag from the header → return value
```

## Ciphertext Layout

The hex string returned by `encrypt()` decodes to:

```
+---------+-----------+----------+----------------------+
| 1 byte  | 1 byte    | 24 bytes | variable             |
+---------+-----------+----------+----------------------+
| VERSION | SERIALIZER| NONCE    | secretbox(MAC || CT) |
+---------+-----------+----------+----------------------+
```

- `VERSION` is always `0x02`.
- `SERIALIZER` is `0x00` for JSON (default), `0x01` for `php_serialize`.
- The 24-byte nonce is `SODIUM_CRYPTO_SECRETBOX_NONCEBYTES`. It is generated
  fresh on every call via `random_bytes()`.
- `secretbox(MAC || CT)` is whatever `sodium_crypto_secretbox()` returns: the
  Poly1305 MAC prepended to the ciphertext, with the same total length as
  plaintext + `SODIUM_CRYPTO_SECRETBOX_MACBYTES` (16).

Unlike the OpenSSL handler, the secretbox MAC authenticates `nonce + box`
implicitly — there is no separate HMAC field.

## Key Derivation

The user key you pass to the handler can be **any non-empty string**. The
handler runs it through BLAKE2b (`sodium_crypto_generichash`) to obtain the
32-byte key that `crypto_secretbox` requires:

```php
$derivedKey = sodium_crypto_generichash(
    $userKey,
    '',                                    // no key for the hash itself
    SODIUM_CRYPTO_SECRETBOX_KEYBYTES       // 32
);
```

Implications:

- The same user key always derives the same 32-byte key, so handlers in two
  PHP processes interoperate with no key-sharing ceremony beyond agreeing on
  the user key.
- The derived key is held in a local variable and zeroed via `sodium_memzero`
  inside a `finally` block. The user key you handed in is **not** zeroed —
  managing that buffer is your responsibility.
- BLAKE2b cannot turn a weak user key into a strong one. If your `key` is
  "password123", that's what the security of the system is worth. See
  [07 — Security](./07-security.md) for what a "real" key looks like.

## Padding

Sodium ciphertext length leaks the plaintext length modulo the block size.
The handler pads inputs with `sodium_pad($payload, $blocksize)` to mitigate
that leak.

- `blocksize` defaults to `16`. Any positive integer is accepted; string
  digits like `'32'` are coerced.
- Larger block size = larger ciphertext = less length-leak. Pick `1` only if
  you genuinely don't care about hiding plaintext length (and want the
  smallest possible ciphertext).
- An explicit `null` falls back to the default of 16. Pass `0`, a negative
  number, a float, or a non-numeric string and you get
  `EncryptionException: The "blocksize" option must be a positive integer.`

## Worked Example: short user key is fine

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Sodium;

$handler = new Sodium(['key' => 'short-key-1234']);   // 14 bytes, < 32
$ct = $handler->encrypt(['session_id' => 'abc']);
$pt = $handler->decrypt($ct);

assert($pt === ['session_id' => 'abc']);
echo "OK\n";
```

The 1.x release silently failed for keys not exactly 32 bytes long. 2.x
derives, so any non-empty string is accepted.

## Worked Example: tampering is rejected by the MAC

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Sodium;
use InitPHP\Encryption\Exceptions\EncryptionException;

$handler = new Sodium(['key' => 'secret']);
$ct = $handler->encrypt('hello');

// Flip a byte inside the secretbox region:
$tampered = $ct;
$tampered[-1] = $ct[-1] === '0' ? '1' : '0';

try {
    $handler->decrypt($tampered);
} catch (EncryptionException $e) {
    echo $e->getMessage(), "\n";
    // → Sodium decryption failed; ciphertext is corrupted or has been tampered with.
}
```

## Worked Example: tuning the padding block size

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Sodium;

$small = new Sodium(['key' => 'k', 'blocksize' => 1]);   // no length hiding
$padded = new Sodium(['key' => 'k', 'blocksize' => 256]); // hide length up to 256 bytes

$shortPlaintext = 'hi';
$ctSmall  = $small->encrypt($shortPlaintext);
$ctPadded = $padded->encrypt($shortPlaintext);

// Both round-trip, but the padded ciphertext is much longer:
assert($small->decrypt($ctSmall) === $shortPlaintext);
assert($padded->decrypt($ctPadded) === $shortPlaintext);
echo strlen($ctSmall), " vs ", strlen($ctPadded), "\n";
// Approx: small=80, padded=592 (hex chars)
```

## Performance Notes

- BLAKE2b key derivation runs on every call. It is fast (~microseconds), but
  if you genuinely need maximum throughput, instantiate the handler once and
  reuse it; per-call overhead is amortised.
- Increasing `blocksize` increases ciphertext size linearly. The CPU cost of
  padding is negligible compared to the secretbox operation itself.
- libsodium uses XSalsa20-Poly1305, which is software-fast on every modern
  platform. There is no equivalent to AES-NI hardware acceleration to worry
  about.

## When to Pick OpenSSL Instead

- You are in an environment where libsodium is not available (rare on modern
  PHP — it ships in core since 7.2).
- Your compliance regime mandates AES (FIPS 140 contexts).
- You need to interoperate with an existing OpenSSL-encrypt-then-MAC
  consumer outside PHP.

If none of those apply, this is the handler you want.

## See Also

- [05 — Options Reference](./05-options.md)
- [06 — Error Handling](./06-error-handling.md)
- [07 — Security](./07-security.md)
