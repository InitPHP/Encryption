# Options Reference

Every handler accepts the same option array. The set of *meaningful* keys
depends on the handler; the rest are ignored. Unknown keys do not raise an
error.

## Quick Reference

| Key | Type | Default | OpenSSL | Sodium | Notes |
| --- | --- | --- | --- | --- | --- |
| `key` | non-empty string | _required_ | ✅ | ✅ | Your secret. Any length. |
| `cipher` | string from `openssl_get_cipher_methods()` | `'AES-256-CTR'` | ✅ | — | Validated at every call. |
| `algo` | string from `hash_hmac_algos()` | `'SHA256'` | ✅ | — | Used both for HKDF and HMAC. |
| `blocksize` | positive integer (or string of digits) | `16` | — | ✅ | `sodium_pad()` block size. |
| `serializer` | `'json'`, `'php_serialize'`, `'php'`, `'serialize'` | `'json'` | ✅ | ✅ | Embedded in the ciphertext header. |

All option keys are **case-insensitive on input** (`'CIPHER'`, `'Cipher'`,
`'cipher'` all set the same thing). They are stored as lower case.

## Precedence

When the same key appears in multiple places, the per-call value wins:

```text
1. encrypt($data, $perCallOptions)      // highest priority
2. $handler->setOption($name, $value)
   $handler->setOptions([...])
3. new OpenSSL([...])                    // constructor / factory
4. BaseHandler::$options defaults        // lowest priority
```

Per-call options never mutate the handler — they are merged into a fresh
array for that single call only.

```php
$handler = new \InitPHP\Encryption\OpenSSL([
    'key' => 'secret',
    'cipher' => 'AES-256-CTR',
]);
$handler->encrypt('x', ['cipher' => 'AES-128-CTR']);
echo $handler->getOption('cipher'); // "AES-256-CTR"
```

## `key` — required

The user-supplied secret. Any non-empty string is accepted.

- Stored as-is on the handler (you can see it via `getOption('key')`).
- Derived to the size each primitive needs:
  - OpenSSL → `hash_hkdf($algo, $key)`, output sized to the hash.
  - Sodium → `sodium_crypto_generichash($key, '', 32)`.
- `null`, an empty string, or any non-string raises
  `EncryptionException: The "key" option is required and must be a non-empty string.`

What "good" looks like:

```php
'key' => getenv('APP_ENCRYPTION_KEY') ?: throw new \RuntimeException('key missing');
```

What "bad" looks like:

```php
'key' => 'password'  // brute-forceable, no entropy.
'key' => null        // throws EncryptionException.
'key' => ''          // throws EncryptionException.
```

Generate a strong key once:

```bash
php -r 'echo bin2hex(random_bytes(32)), "\n";'
```

## `cipher` — OpenSSL only

The OpenSSL cipher name as accepted by `openssl_encrypt()`. Validated against
`openssl_get_cipher_methods()` (case-insensitive) on every call; an unknown
value raises `EncryptionException: Unknown OpenSSL cipher "…"`.

| Value | Notes |
| --- | --- |
| `'AES-256-CTR'` (default) | Stream-mode AES, no padding, 16-byte IV. |
| `'AES-256-CBC'` | Block-mode AES with PKCS#7 padding. Slightly bigger ciphertext. |
| `'AES-128-CTR'` / `'AES-128-CBC'` | Same shapes with smaller derived key. |
| `'ChaCha20'` | Stream cipher; OpenSSL ≥1.1 required. |

Do **not** use GCM modes (`AES-256-GCM`, `ChaCha20-Poly1305`) here — the
handler does not surface OpenSSL's separate auth tag. Use the Sodium handler
if you want AEAD.

## `algo` — OpenSSL only

The hashing algorithm used in two places:

1. HKDF to derive the per-handler secret from your user key.
2. HMAC to authenticate the ciphertext.

Validated against `hash_hmac_algos()` (case-insensitive) on every call.

| Value | Notes |
| --- | --- |
| `'SHA256'` (default) | Universal, fast. 32-byte HMAC. |
| `'SHA512'` | Stronger; 64-byte HMAC adds 32 bytes per ciphertext. |
| `'SHA3-256'` / `'SHA3-512'` | SHA-3 family. |
| `'MD5'`, `'SHA1'` | Technically accepted, not recommended. |

## `blocksize` — Sodium only

Block size used for `sodium_pad()` and `sodium_unpad()` to hide the exact
plaintext length.

- Must be a **positive integer**. String digits like `'32'` are coerced
  (`(int) '32' === 32`).
- An explicit `null` falls back to the default `16` via PHP's `??` operator.
- `0`, negative numbers, floats, arrays, and non-numeric strings raise
  `EncryptionException: The "blocksize" option must be a positive integer.`
- Larger values give more length-hiding but produce proportionally larger
  ciphertexts.

## `serializer`

Picks how `encrypt()` turns your `mixed` payload into bytes (and how
`decrypt()` reverses that).

| Value | Flag byte | Behaviour |
| --- | --- | --- |
| `'json'` (default), `'JSON'` | `0x00` | `json_encode` / `json_decode` with `JSON_THROW_ON_ERROR`. Safe (no objects instantiated). Cannot carry raw binary bytes. |
| `'php_serialize'`, `'php'`, `'serialize'`, `'SERIALIZE'` | `0x01` | `serialize()` / `unserialize($data, ['allowed_classes' => false])`. 8-bit clean. Custom objects degrade to `__PHP_Incomplete_Class` on decode. |

The flag byte is embedded in the ciphertext header (byte 1), so `decrypt()`
always restores using the same serializer `encrypt()` chose, even if you
change the option in between.

Unknown serializer names raise
`EncryptionException: Unknown "serializer" option: …`.

## Reading Options Back

```php
$handler->getOption('cipher');               // current value, default if unset
$handler->getOption('foo', 'fallback');      // returns 'fallback' if unset
$handler->getOptions();                       // entire array
```

Keys passed to `getOption()` are lowercased before lookup, matching the
case-insensitive write side.

## Writing Custom Option Keys

Custom handlers can store anything in the options array — there is no
declared schema. Read with `$this->resolveOptions($options)['my_key'] ?? …`
inside `encrypt()` / `decrypt()`.

See [04 — Custom Handlers](./04-custom-handlers.md) for a worked example.

## See Also

- [02 — OpenSSL Handler](./02-openssl-handler.md) for the cipher/algo
  trade-offs in context.
- [03 — Sodium Handler](./03-sodium-handler.md) for the blocksize/padding
  trade-offs.
- [06 — Error Handling](./06-error-handling.md) for every option-related
  exception message.
