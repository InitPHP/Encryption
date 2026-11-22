# Configuration Options

Every handler accepts the same option array. The set of *meaningful* keys
depends on the handler; unknown keys are ignored without an error.

## At a Glance

| Option | Type | Default | OpenSSL | Sodium | Notes |
| --- | --- | --- | :---: | :---: | --- |
| `key` | non-empty string | _required_ | ✅ | ✅ | Your secret. Any length. |
| `cipher` | string from `openssl_get_cipher_methods()` | `'AES-256-CTR'` | ✅ | — | Validated at every call. |
| `algo` | string from `hash_hmac_algos()` | `'SHA256'` | ✅ | — | Used both for HKDF and HMAC. |
| `blocksize` | positive integer (digit string ok) | `16` | — | ✅ | `sodium_pad()` block size. |
| `serializer` | `'json'`, `'php_serialize'`, `'php'`, `'serialize'` | `'json'` | ✅ | ✅ | Embedded in the ciphertext header. |

All keys are **case-insensitive on input** (`'CIPHER'`, `'Cipher'`,
`'cipher'` all set the same option) and are stored as lower case.

## Where Options Can Be Set

```text
1. encrypt($data, $perCallOptions)     ← highest priority
2. $handler->setOption($name, $value)
   $handler->setOptions([...])
3. new OpenSSL([...]) / Encrypt::use(OpenSSL::class, [...])
4. BaseHandler::$options defaults      ← lowest priority
```

Per-call options never mutate the handler — they are merged into a fresh
array for that single call only.

```php
$handler = new \InitPHP\Encryption\OpenSSL([
    'key'    => 'secret',
    'cipher' => 'AES-256-CTR',
]);
$handler->encrypt('x', ['cipher' => 'AES-128-CTR']);
echo $handler->getOption('cipher'); // "AES-256-CTR"
```

## Per-Option Reference

### `key` — required, all handlers

The user-supplied secret. Any non-empty string is accepted.

- Stored as-is on the handler (`$handler->getOption('key')` returns it).
- Derived to the size each primitive needs:
  - OpenSSL → `hash_hkdf($algo, $key)` (output size = hash size).
  - Sodium → `sodium_crypto_generichash($key, '', 32)`.
- `null`, empty string, or any non-string raises:
  `EncryptionException: The "key" option is required and must be a non-empty string.`

What "good" looks like:

```php
'key' => getenv('APP_ENCRYPTION_KEY')
    ?: throw new \RuntimeException('APP_ENCRYPTION_KEY is not set');
```

What "bad" looks like:

```php
'key' => 'password' // low entropy; the handler accepts it but the system's
                   // security is only as good as that string.
'key' => null      // throws EncryptionException.
'key' => ''        // throws EncryptionException.
```

Generate a real key once:

```bash
php -r 'echo bin2hex(random_bytes(32)), "\n";'
# → 64-character hex string, 256 bits of entropy.
```

### `cipher` — OpenSSL only

The OpenSSL cipher name as accepted by `openssl_encrypt()`. Validated
against `openssl_get_cipher_methods()` (case-insensitive) at every call;
unknown values raise `EncryptionException: Unknown OpenSSL cipher "…"`.

| Value | Notes |
| --- | --- |
| `'AES-256-CTR'` (default) | Stream-mode AES, no padding, 16-byte IV. |
| `'AES-256-CBC'` | Block-mode AES with PKCS#7 padding. |
| `'AES-128-CTR'` / `'AES-128-CBC'` | Same shapes, smaller derived key. |
| `'ChaCha20'` | Stream cipher; OpenSSL ≥1.1 required. |

**Do not** use GCM modes (`AES-256-GCM`, `ChaCha20-Poly1305`) — see
[OpenSSL Handler](OpenSSL-Handler.md) for why.

### `algo` — OpenSSL only

The hashing algorithm used both for HKDF (deriving the secret from your
user key) and for HMAC (authenticating the ciphertext). Validated against
`hash_hmac_algos()` (case-insensitive).

| Value | HMAC output | Notes |
| --- | --- | --- |
| `'SHA256'` (default) | 32 bytes | Universal, fast. |
| `'SHA512'` | 64 bytes | Stronger; +32 bytes per ciphertext. |
| `'SHA3-256'` / `'SHA3-512'` | 32 / 64 bytes | SHA-3 family. |

`MD5` and `SHA1` are technically accepted but not recommended.

### `blocksize` — Sodium only

Block size for `sodium_pad()` / `sodium_unpad()`. Hides exact plaintext
length up to the next multiple of this value.

- Must be a **positive integer**. Digit strings like `'32'` are coerced.
- Explicit `null` falls back to the default of 16 (via PHP's `??`).
- `0`, negative numbers, floats, arrays, and non-numeric strings raise:
  `EncryptionException: The "blocksize" option must be a positive integer.`
- Larger value → more length-hiding → bigger ciphertext.

### `serializer`

Picks how `encrypt()` turns your `mixed` payload into bytes (and how
`decrypt()` reverses it). The choice is **embedded in the ciphertext
header** (byte 1), so `decrypt()` always restores using the same serializer
`encrypt()` chose, even if you change the option between calls.

| Value | Flag byte | Behaviour |
| --- | :---: | --- |
| `'json'` (default) | `0x00` | `json_encode`/`json_decode` with `JSON_THROW_ON_ERROR`. Safe (no classes instantiated). Cannot carry raw binary bytes. |
| `'php_serialize'`, `'php'`, `'serialize'` | `0x01` | `serialize()`/`unserialize($_, ['allowed_classes' => false])`. 8-bit clean. Custom objects degrade to `__PHP_Incomplete_Class`. |

Unknown serializer names raise
`EncryptionException: Unknown "serializer" option: …`.

See [Serialization](Serialization.md) for the full comparison.

## Reading Options Back

```php
$handler->getOption('cipher');           // current value, default if unset
$handler->getOption('foo', 'fallback');  // returns 'fallback' if 'foo' is unset
$handler->getOptions();                   // entire merged options array
```

`getOption()` lowercases the key before lookup, matching the case-insensitive
write side.

## Writing Custom Option Keys

Custom handlers can store anything in the options array — there is no
schema. Read with `$this->resolveOptions($options)['my_key'] ?? …` inside
`encrypt()` / `decrypt()`. See [Custom Handlers](Custom-Handlers.md) for an
example.

## See Also

- [OpenSSL Handler](OpenSSL-Handler.md) — cipher/algo trade-offs in context.
- [Sodium Handler](Sodium-Handler.md) — blocksize/padding trade-offs.
- [Serialization](Serialization.md) — JSON vs PHP serialize, when to switch.
- [Error Handling](Error-Handling.md) — every option-related exception
  message.
