# OpenSSL Handler

`InitPHP\Encryption\OpenSSL` is an *encrypt-then-MAC* authenticated
encryption handler built on `ext-openssl` and `hash_hmac()`. Pick it if you
need control over the symmetric cipher (FIPS-friendly AES variants, for
example), or if libsodium is not available in your environment.

> If you have no specific cipher requirement, use the
> [Sodium handler](Sodium-Handler.md) instead. Its construction has no knobs
> to mis-set.

## Quickstart

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\OpenSSL;

$handler = Encrypt::use(OpenSSL::class, [
    'key'    => getenv('APP_ENCRYPTION_KEY'),
    // defaults — included here only to show what's used:
    'cipher' => 'AES-256-CTR',
    'algo'   => 'SHA256',
]);

$ct = $handler->encrypt(['user_id' => 42]);
$pt = $handler->decrypt($ct);
```

## What the Handler Does

```text
encrypt($data, $options)
    1. Resolve options (per-call merged on top of persistent options)
    2. Require non-empty 'key'
    3. Validate 'cipher' against openssl_get_cipher_methods()
    4. Validate 'algo' against hash_hmac_algos()
    5. Derive secret = hash_hkdf($algo, $key)
    6. Generate fresh IV = random_bytes(openssl_cipher_iv_length($cipher))
    7. Serialize $data via the configured serializer (default: JSON)
    8. ciphertext = openssl_encrypt(..., OPENSSL_RAW_DATA, $iv)
    9. hmac = hash_hmac($algo, VERSION||SERIALIZER||IV||ciphertext, secret, raw=true)
   10. return bin2hex(VERSION || SERIALIZER || HMAC || IV || ciphertext)

decrypt($data, $options)
    1. Resolve options, require key, validate cipher and algo
    2. binary = hex2bin($data)
    3. Read 2-byte header; reject if version byte ≠ 0x02
    4. secret = hash_hkdf($algo, $key)
    5. Read HMAC (length = strlen(hash_hmac($algo, '', '', true)))
    6. Read IV (length = openssl_cipher_iv_length($cipher))
    7. Recompute HMAC; hash_equals() against the wire HMAC
    8. openssl_decrypt(..., OPENSSL_RAW_DATA, $iv) → plaintext bytes
    9. Deserialize via the serializer flag from the header → return value
```

Every step that can fail raises `EncryptionException` — see
[Error Handling](Error-Handling.md).

## Ciphertext Layout

The hex string returned by `encrypt()` decodes to:

```
+---------+-----------+---------+---------+----------------+
| 1 byte  | 1 byte    | N bytes | M bytes | variable       |
+---------+-----------+---------+---------+----------------+
| VERSION | SERIALIZER| HMAC    | IV      | ciphertext     |
+---------+-----------+---------+---------+----------------+
```

- `VERSION` is `0x02` for every ciphertext this handler produces in 2.x.
- `SERIALIZER` is `0x00` for JSON (default), `0x01` for `php_serialize`.
- `N` equals `strlen(hash_hmac($algo, '', '', true))` — 32 for SHA-256,
  64 for SHA-512, and so on. Switching the algorithm changes the layout
  automatically.
- `M` equals `openssl_cipher_iv_length($cipher)` — 16 for AES-CTR /
  AES-CBC, 0 for ciphers that take no IV.

The HMAC authenticates `VERSION || SERIALIZER || IV || ciphertext`, so the
serializer byte is inside the authenticated region. An attacker cannot
flip the serializer flag to trick the decoder into running a different
unserialiser on the same bytes.

See [Ciphertext Format](Ciphertext-Format.md) for the cross-handler comparison.

## Choosing a Cipher

`openssl_get_cipher_methods()` returns ~150 entries on a typical install.
Pick one of these in production:

| Cipher | Notes |
| --- | --- |
| `AES-256-CTR` (default) | Stream-style, fast, no padding, 16-byte IV. |
| `AES-256-CBC` | Block-mode AES with PKCS#7 padding. Ciphertext rounded up to the block size. |
| `AES-128-CTR` / `AES-128-CBC` | Same modes with a 128-bit derived key. |
| `ChaCha20` | Stream cipher; nice on platforms without AES-NI. Requires OpenSSL 1.1+. |

### Do not use GCM modes here

Do **not** pass `AES-256-GCM` or `ChaCha20-Poly1305` to this handler. GCM
modes expect their authentication tag tracked separately via
`openssl_encrypt`'s `$tag` parameter, which this handler does not surface.
The encrypt-then-MAC path would still be applied (double-authentication),
and the GCM tag itself would be missing from the wire. **For an AEAD
construction, use the [Sodium handler](Sodium-Handler.md) instead.**

## Choosing a Hash Algorithm

`algo` plays two roles:

1. **HKDF**: derives the per-handler secret from your user key.
2. **HMAC**: authenticates the ciphertext.

Both use the same algorithm. Anything in `hash_hmac_algos()` is accepted.
Reasonable choices:

| Value | HMAC output | Notes |
| --- | --- | --- |
| `SHA256` (default) | 32 bytes | Universal, fast. |
| `SHA512` | 64 bytes | Stronger; adds 32 bytes per ciphertext. |
| `SHA3-256` / `SHA3-512` | 32 / 64 bytes | SHA-3 family if you prefer it. |

`MD5` and `SHA1` are accepted (and functional) but not recommended.

## Examples

### Switching cipher per call

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\OpenSSL;

$handler = Encrypt::use(OpenSSL::class, [
    'key'    => 'a-real-secret',
    'cipher' => 'AES-256-CTR', // handler default
]);

$small = $handler->encrypt('cookie payload');
$big   = $handler->encrypt('CBC payload', ['cipher' => 'AES-256-CBC']);

// Per-call options DO NOT mutate the handler:
echo $handler->getOption('cipher'); // "AES-256-CTR"

// The cipher is not embedded in the wire format, so you must pass the
// same override when decrypting:
echo $handler->decrypt($big, ['cipher' => 'AES-256-CBC']); // "CBC payload"
```

### Tampering is detected

```php
use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Exceptions\EncryptionException;

$handler = new OpenSSL(['key' => 'secret']);
$ct = $handler->encrypt('hello');

// Flip one hex character (= flip 4 bits in the underlying binary):
$tampered = $ct;
$tampered[-1] = $ct[-1] === '0' ? '1' : '0';

try {
    $handler->decrypt($tampered);
} catch (EncryptionException $e) {
    echo $e->getMessage(), PHP_EOL;
    // → HMAC verification failed; ciphertext is corrupted or has been tampered with.
}
```

### Round-trip a custom hash algorithm

```php
use InitPHP\Encryption\OpenSSL;

$handler = new OpenSSL([
    'key'    => 'secret',
    'algo'   => 'sha512',          // 64-byte HMAC
    'cipher' => 'AES-256-CBC',
]);

$ct = $handler->encrypt(['user_id' => 1]);
$pt = $handler->decrypt($ct);
// $pt === ['user_id' => 1]
```

## Performance Notes

- HKDF runs on every call. The per-call cost is dominated by OpenSSL itself,
  not the derivation; you do not need to cache the derived secret.
- `AES-256-CTR` is faster than `AES-256-CBC` on modern CPUs because there
  is no padding. It is the default for that reason.
- HMAC-SHA-256 vs HMAC-SHA-512 makes a measurable difference only at large
  payload sizes (multi-megabyte). For typical cookie / session payloads the
  choice is in the noise.

## When to Pick Sodium Instead

- You want a single primitive that just works, with no knobs.
- libsodium is available (it ships with PHP core).
- You need the slight speed edge of XChaCha20-Poly1305 on platforms without
  AES-NI.

If none of those apply, OpenSSL is a perfectly reasonable production
choice.

## See Also

- [Sodium Handler](Sodium-Handler.md) — the other built-in handler.
- [Configuration Options](Configuration-Options.md) — every option in detail.
- [Ciphertext Format](Ciphertext-Format.md) — wire format reference.
- [Error Handling](Error-Handling.md) — every `EncryptionException` you may
  see.
- [Security Best Practices](Security-Best-Practices.md) — threat model and key
  management.
