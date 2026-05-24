# OpenSSL Handler

`InitPHP\Encryption\OpenSSL` is an encrypt-then-MAC handler built on
`ext-openssl` and `hash_hmac()`. It is the right choice when you need control
over the symmetric cipher (e.g. for FIPS environments) or when libsodium is
not available.

## What the Handler Does Per Call

```text
encrypt($data, $options)
    1. resolve options (per-call options merged on top of handler defaults)
    2. require a non-empty 'key' option
    3. validate 'cipher' against openssl_get_cipher_methods()
    4. validate 'algo' against hash_hmac_algos()
    5. derive a per-handler secret: hash_hkdf($algo, $key)
    6. generate a fresh IV: random_bytes(openssl_cipher_iv_length($cipher))
    7. serialize $data via the configured serializer (default: JSON)
    8. openssl_encrypt(..., OPENSSL_RAW_DATA, $iv) → ciphertext bytes
    9. authenticate VERSION || SERIALIZER || IV || CIPHERTEXT with HMAC
   10. return bin2hex(VERSION || SERIALIZER || HMAC || IV || CIPHERTEXT)

decrypt($data, $options)
    1. resolve options, require key, validate cipher and algo (same as above)
    2. hex2bin → binary
    3. read the 2-byte header; reject if version byte ≠ 0x02
    4. recompute the derived secret from the key and algo
    5. read HMAC (size = strlen(hash_hmac($algo, '', '', true)))
    6. read IV (size = openssl_cipher_iv_length($cipher))
    7. recompute the HMAC; hash_equals() against the one read from the wire
    8. openssl_decrypt(..., OPENSSL_RAW_DATA, $iv) → plaintext bytes
    9. deserialize per the serializer flag from the header → return value
```

## Ciphertext Layout

The hex string returned by `encrypt()` decodes to:

```
+---------+-----------+--------+--------+----------------+
| 1 byte  | 1 byte    | N bytes| M bytes| variable       |
+---------+-----------+--------+--------+----------------+
| VERSION | SERIALIZER| HMAC   | IV     | ciphertext     |
+---------+-----------+--------+--------+----------------+
```

- `VERSION` is `0x02` for every ciphertext this handler produces.
- `SERIALIZER` is `0x00` for JSON (default), `0x01` for `php_serialize`.
- `N` is `strlen(hash_hmac($algo, '', '', true))` — 32 for SHA-256, 64 for
  SHA-512, etc. Computed at decrypt time, so changing the algorithm changes
  the layout naturally.
- `M` is `openssl_cipher_iv_length($cipher)` — 0 for stream ciphers without
  an IV (rare), 16 for AES-CTR / AES-CBC, etc.

The HMAC authenticates `VERSION || SERIALIZER || IV || ciphertext`. The
serializer byte is inside the authenticated region, so an attacker cannot
flip it to trick the decoder.

## Choosing a Cipher

`openssl_get_cipher_methods()` returns ~150 entries on a typical install.
You almost certainly want one of these:

| Cipher | Notes |
| --- | --- |
| `AES-256-CTR` (default) | Stream-style, fast, no padding required, 128-bit IV. |
| `AES-256-CBC` | Classical block mode. Larger ciphertext (block-aligned). |
| `AES-128-CTR` / `AES-128-CBC` | Same shapes, 128-bit key derived from the HKDF output. |
| `ChaCha20` | Stream cipher; nice on platforms without AES-NI. Requires `ext-openssl` linked against OpenSSL 1.1+. |

Do **not** use GCM modes (`AES-256-GCM`, `ChaCha20-Poly1305`) with this
handler. GCM ciphers expect their authentication tag to be tracked separately
via `openssl_encrypt`'s `$tag` parameter, which this handler does not surface.
The HMAC-then-encrypt construction would double-authenticate and the tag
would still be missing from the wire. If you want AEAD, use the
[Sodium handler](./03-sodium-handler.md) instead.

## Choosing a Hash Algorithm

`algo` is used in two places:

1. **HKDF** turns your user key into a per-cipher derived key.
2. **HMAC** authenticates the ciphertext.

Anything from `hash_hmac_algos()` works; pick something modern:

- `SHA256` (default) — universally available, good performance.
- `SHA512` — stronger; ~2× HMAC output size (64 bytes), so ciphertexts grow
  by 32 bytes.
- `SHA3-256` / `SHA3-512` — fine if you prefer the SHA-3 family.

`MD5` and `SHA1` are technically accepted by `hash_hmac_algos()` and
technically functional but are not recommended.

## Worked Example: switching ciphers per call

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\OpenSSL;

$handler = Encrypt::use(OpenSSL::class, [
    'key' => 'a-real-secret',
    'cipher' => 'AES-256-CTR',   // default for the handler
]);

$small = $handler->encrypt('cookie payload');
$big   = $handler->encrypt('CBC payload', ['cipher' => 'AES-256-CBC']);

// Per-call options do NOT mutate the handler:
echo $handler->getOption('cipher'); // "AES-256-CTR"

// Decryption reads the cipher from the handler's current options, so you
// must pass the same per-call override when decrypting:
echo $handler->decrypt($big, ['cipher' => 'AES-256-CBC']); // "CBC payload"
```

The handler does not embed the cipher or algorithm in the ciphertext header —
only the format version and serializer flag. If you change them across calls,
you are responsible for tracking which ciphertext used which configuration.
In practice almost everyone picks one set of options at deployment time and
never overrides per-call.

## Worked Example: HMAC tampering is detected

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Exceptions\EncryptionException;

$handler = new OpenSSL(['key' => 'secret']);
$ct = $handler->encrypt('hello');

// Flip one byte deep in the ciphertext:
$tampered = $ct;
$tampered[-1] = $ct[-1] === '0' ? '1' : '0';

try {
    $handler->decrypt($tampered);
} catch (EncryptionException $e) {
    echo $e->getMessage(), "\n";
    // → HMAC verification failed; ciphertext is corrupted or has been tampered with.
}
```

## Performance Notes

- HKDF is computed on every `encrypt()` and `decrypt()` call. For very
  high-throughput cases (>10k ops/s), construct the handler once and reuse
  it; the per-call cost is dominated by OpenSSL, not the option resolution.
- `AES-256-CTR` is faster than `AES-256-CBC` on modern CPUs (no padding) and
  is the default for that reason.
- HMAC-SHA256 is dominant in the per-call cost for tiny payloads (<1 KiB).
  Switching to SHA-512 makes a measurable difference only at multi-megabyte
  payload sizes.

## When to Pick Sodium Instead

- You want a single primitive that "just works" — no cipher knob, no
  algorithm knob, no IV / HMAC layout in your head.
- You are happy with libsodium being a hard dependency.
- You need the slight speed edge of XChaCha20-Poly1305 on platforms without
  AES-NI.

If none of those apply, OpenSSL is a perfectly reasonable production choice.

## See Also

- [05 — Options Reference](./05-options.md) — every option, default, range.
- [06 — Error Handling](./06-error-handling.md) — every `EncryptionException`
  this handler can throw.
- [07 — Security](./07-security.md) — threat model and key management.
