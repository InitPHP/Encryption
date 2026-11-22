# Sodium Handler

`InitPHP\Encryption\Sodium` wraps libsodium's `crypto_secretbox` AEAD
construction (XSalsa20-Poly1305 under the hood). It is the recommended
default: the underlying primitive has no tunables, the API is hard to
misuse, and authentication is part of the construction rather than
something you bolt on afterwards.

## Quickstart

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, [
    'key' => getenv('APP_ENCRYPTION_KEY'),
    // optional, default is 16:
    // 'blocksize' => 16,
]);

$ct = $handler->encrypt(['user_id' => 42]);
$pt = $handler->decrypt($ct);
```

That's the whole API. There is no `cipher` to choose, no `algo` to choose;
the construction is fixed by libsodium.

## What the Handler Does

```text
encrypt($data, $options)
    1. Resolve options (per-call merged on top of persistent options)
    2. Require non-empty 'key'
    3. Resolve 'blocksize' (default 16; must be positive integer)
    4. derivedKey = sodium_crypto_generichash(
                       $userKey, '',
                       SODIUM_CRYPTO_SECRETBOX_KEYBYTES // 32
                    )
    5. Serialize $data via the configured serializer (default: JSON)
    6. padded = sodium_pad($serialized, $blocksize)
    7. nonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) // 24
    8. box    = sodium_crypto_secretbox($padded, $nonce, $derivedKey)
    9. sodium_memzero($derivedKey)            ← always, even on exception
   10. return bin2hex(VERSION || SERIALIZER || NONCE || BOX)

decrypt($data, $options)
    1. Resolve options, require key, resolve blocksize
    2. binary = hex2bin($data)
    3. Reject if shorter than 2 + nonce + MAC bytes
    4. Read 2-byte header; reject if version byte ≠ 0x02
    5. Read 24-byte nonce
    6. derivedKey = same BLAKE2b derivation as encrypt()
    7. padded = sodium_crypto_secretbox_open(...)  ← fails if MAC wrong
    8. payload = sodium_unpad($padded, $blocksize)
    9. sodium_memzero($derivedKey)
   10. Deserialize via the serializer flag from the header → return value
```

Every step that can fail raises `EncryptionException` — see
[Error Handling](Error-Handling.md).

## Ciphertext Layout

```
+---------+-----------+----------+----------------------+
| 1 byte  | 1 byte    | 24 bytes | variable             |
+---------+-----------+----------+----------------------+
| VERSION | SERIALIZER| NONCE    | secretbox(MAC || CT) |
+---------+-----------+----------+----------------------+
```

- `VERSION` is `0x02` for every ciphertext this handler produces in 2.x.
- `SERIALIZER` is `0x00` for JSON (default), `0x01` for `php_serialize`.
- The 24-byte nonce is `SODIUM_CRYPTO_SECRETBOX_NONCEBYTES`. A fresh nonce
  is generated for every call via `random_bytes()` (the OS CSPRNG).
- `secretbox(MAC || CT)` is whatever `sodium_crypto_secretbox()` returns:
  the Poly1305 MAC prepended to the encrypted bytes, with total length =
  plaintext + `SODIUM_CRYPTO_SECRETBOX_MACBYTES` (16).

Unlike the OpenSSL handler, the secretbox MAC authenticates `nonce + box`
implicitly — there is no separate HMAC field on the wire.

See [Ciphertext Format](Ciphertext-Format.md) for the cross-handler
comparison.

## Key Derivation

You can pass **any non-empty string** as the user key. The handler runs it
through BLAKE2b (`sodium_crypto_generichash`) to obtain the 32-byte key
`crypto_secretbox` requires:

```php
$derivedKey = sodium_crypto_generichash(
    $userKey,
    '',                                    // no key for the hash itself
    SODIUM_CRYPTO_SECRETBOX_KEYBYTES       // 32
);
```

Consequences:

- The same user key always derives the same 32-byte key, so two processes
  with the same user key interoperate with no key-sharing ceremony beyond
  agreeing on that string.
- The derived key is held in a local buffer and zeroed via
  `sodium_memzero()` in a `finally` block — even if encryption or
  decryption throws.
- The user key you passed in is **not** zeroed. Managing that buffer is
  your responsibility.
- BLAKE2b cannot turn a weak user key into a strong one. If your `key` is
  `"password123"`, that is what the security of the system is worth. See
  [Security Best Practices](Security-Best-Practices.md).

## Padding

Plaintext length leaks through ciphertext length. The Sodium handler pads
the serialised payload with `sodium_pad($payload, $blocksize)` to
mitigate that.

- `blocksize` defaults to `16`. Any positive integer is accepted; digit
  strings like `'32'` are coerced.
- Larger block size → bigger ciphertext → less length leakage. Use `1` only
  if you genuinely do not care about hiding plaintext length.
- An explicit `null` falls back to the default of 16. `0`, negatives,
  floats, or non-numeric strings raise
  `EncryptionException: The "blocksize" option must be a positive integer.`

## Examples

### Short user key works

```php
use InitPHP\Encryption\Sodium;

$handler = new Sodium(['key' => 'short-key-1234']); // 14 bytes, < 32
$ct = $handler->encrypt(['session_id' => 'abc']);
$pt = $handler->decrypt($ct);
// $pt === ['session_id' => 'abc']
```

In 1.x, this silently broke with a `SodiumException` deep in
`crypto_secretbox`. 2.x derives, so any non-empty string works.

### Tampering is rejected by the MAC

```php
use InitPHP\Encryption\Sodium;
use InitPHP\Encryption\Exceptions\EncryptionException;

$handler = new Sodium(['key' => 'secret']);
$ct = $handler->encrypt('hello');

$tampered = $ct;
$tampered[-1] = $ct[-1] === '0' ? '1' : '0';

try {
    $handler->decrypt($tampered);
} catch (EncryptionException $e) {
    echo $e->getMessage(), PHP_EOL;
    // → Sodium decryption failed; ciphertext is corrupted or has been tampered with.
}
```

### Tuning the padding block size

```php
use InitPHP\Encryption\Sodium;

$small  = new Sodium(['key' => 'k', 'blocksize' => 1]);   // no length hiding
$padded = new Sodium(['key' => 'k', 'blocksize' => 256]); // hide up to 256 bytes

$ctSmall  = $small->encrypt('hi');
$ctPadded = $padded->encrypt('hi');

echo strlen($ctSmall), ' vs ', strlen($ctPadded), PHP_EOL;
// Approx: 80 vs 592 hex characters
```

### Two handlers, same key, interoperate

```php
use InitPHP\Encryption\Sodium;

$writer = new Sodium(['key' => 'same-user-key']);
$reader = new Sodium(['key' => 'same-user-key']);

echo $reader->decrypt($writer->encrypt('hello')); // → hello
```

## Performance Notes

- BLAKE2b key derivation runs on every call. It costs microseconds; you do
  not need to cache the derived key.
- Increasing `blocksize` increases ciphertext size linearly. The CPU cost
  of padding is negligible compared to the secretbox operation.
- XSalsa20-Poly1305 is software-fast on every modern platform — there is
  no AES-NI hardware-acceleration story to worry about.

## When to Pick OpenSSL Instead

- libsodium is not available in your environment (rare on PHP 7.2+).
- Your compliance regime mandates AES (FIPS 140 contexts).
- You need to interoperate with an existing OpenSSL-encrypt-then-MAC
  consumer outside PHP.

Otherwise, Sodium is the handler you want.

## See Also

- [OpenSSL Handler](OpenSSL-Handler.md) — the other built-in handler.
- [Configuration Options](Configuration-Options.md) — every option in detail.
- [Ciphertext Format](Ciphertext-Format.md) — wire format reference.
- [Error Handling](Error-Handling.md) — every `EncryptionException`.
- [Security Best Practices](Security-Best-Practices.md) — threat model and key
  management.
