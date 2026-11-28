# Troubleshooting

Symptom-first guide. Find the message you saw or the behaviour you got;
each entry tells you what's almost certainly going on and how to confirm.

For the canonical, full list of every error message, see
[Error Handling](Error-Handling.md).

## The "openssl" extension is required by the OpenSSL handler.

You constructed `InitPHP\Encryption\OpenSSL` on a PHP build without
`ext-openssl` loaded.

**Confirm:**

```bash
php -m | grep -i openssl
```

If nothing prints, install it. On Ubuntu/Debian:

```bash
sudo apt install php-openssl    # or php8.2-openssl, depending on version
```

On macOS Homebrew, `php` ships with openssl bundled — if it isn't loaded,
check `php --ini` to see which `php.ini` is active and confirm `extension
=openssl` is enabled.

If you can't add the extension, switch to the [Sodium](Sodium-Handler.md)
handler.

## The "sodium" extension is required by the Sodium handler.

Same story for `ext-sodium`. Sodium has been **part of PHP core since
7.2**, so this is rare on modern installs. Confirm:

```bash
php -m | grep -i sodium
```

If `sodium` isn't there, your PHP build was compiled `--disable-sodium` or
the binary distribution stripped it. Reinstall PHP with the extension
enabled, or switch to OpenSSL.

## The "key" option is required and must be a non-empty string.

You called `encrypt()` (or `decrypt()`) on a handler that has no `key`
configured, or `key` is `null`, `''`, or not a string.

**Common causes:**

- Forgot to pass `['key' => …]` to the constructor / factory.
- Forgot the env var that supplies the key:

  ```php
  $key = getenv('APP_ENCRYPTION_KEY')
      ?: throw new RuntimeException('APP_ENCRYPTION_KEY is not set');
  $h = new \InitPHP\Encryption\Sodium(['key' => $key]);
  ```

- Passing a non-string (e.g. an `int` accidentally cast through `(string)`
  somewhere).

## Unknown OpenSSL cipher "…". / Unknown HMAC hashing algorithm "…".

You passed a `cipher` or `algo` value the PHP build doesn't support.

**Confirm what your build supports:**

```php
print_r(openssl_get_cipher_methods());   // every cipher you can use
print_r(hash_hmac_algos());              // every HMAC algo you can use
```

Validation is **case-insensitive**, so `'aes-256-ctr'` and `'AES-256-CTR'`
both work — but `'AES256-CTR'` (no dash) does not.

## "Unsupported ciphertext format version 0x01; expected 0x02. Ciphertexts produced by 1.x are not readable by 2.x."

A 1.x-shaped ciphertext was fed to a 2.x handler.

This is the **expected** behaviour — 2.x is a deliberate format break.
See [Migration from 1.x](Migration-from-1.x.md) for the re-encryption
recipe.

If you can't migrate yet, pin `composer require initphp/encryption:^1.0`
and stay on 1.x. (Note: only the latest stable major receives security
fixes — see [`SECURITY.md`](https://github.com/InitPHP/.github/blob/main/SECURITY.md).)

## "HMAC verification failed; ciphertext is corrupted or has been tampered with." (OpenSSL) / "Sodium decryption failed; ciphertext is corrupted or has been tampered with." (Sodium)

Authentication check failed. One of three things is true:

1. **The ciphertext was modified in transit/storage.**
   - A column truncation? Check the column type (`VARCHAR(255)` cutting a
     long hex string is a classic cause).
   - URL percent-encoding turning back into a different byte? Hex is
     URL-safe, but check that nothing in your middleware decoded it
     anyway.
   - Cookie value got URL-encoded somewhere it shouldn't have been.

2. **The key on the decrypt side does not match the encrypt side.**
   - Different env on dev vs prod?
   - Key rotated, but the ciphertext is older than the rotation? See
     [Recipes #6](Recipes.md#6-key-rotation-with-fallback-decrypt).

3. **An actual attacker is trying random / modified ciphertexts.**

Log enough context (source IP, count over time) to differentiate (1)+(2)
from (3). Do **not** log the ciphertext itself.

## "Ciphertext is not valid hex-encoded data."

Whatever you passed to `decrypt()` was not even-length hexadecimal.

**Common causes:**

- An empty string. Check `if ($ct === '') return null;` upstream of the
  decrypt call.
- A base64-encoded ciphertext (someone in your pipeline ran
  `base64_encode()` on it). Hex, not base64, is this package's wire format.
- Mojibake from a misconfigured DB connection — confirm UTF-8 / ascii
  client encoding all the way through.

## "Failed to JSON-encode payload: Malformed UTF-8 characters, possibly incorrectly encoded"

Your payload contains raw binary bytes (or invalid UTF-8). JSON is not
8-bit-clean.

**Fix:** switch to PHP serializer for that handler:

```php
$h = new \InitPHP\Encryption\Sodium([
    'key'        => 'k',
    'serializer' => 'php_serialize',
]);
```

See [Serialization](Serialization.md).

## `decrypt()` returns `__PHP_Incomplete_Class` instead of my class

By design: the PHP serializer is always invoked with `['allowed_classes'
=> false]` to neutralise object-injection attacks. Custom classes survive
the encode side but degrade to `__PHP_Incomplete_Class` on decode.

**Fix:** encrypt a plain array describing the object, reconstruct on the
read side:

```php
$ct = $h->encrypt(['type' => 'User', 'name' => 'alice']);
$arr = $h->decrypt($ct);
$user = new User($arr['name']);
```

## The "blocksize" option must be a positive integer.

Sodium handler. You passed something other than a positive integer for
`blocksize`.

Accepted: any positive int (`1`, `16`, `256`), digit-strings (`'32'`),
or omitting the option (defaults to 16). An explicit `null` falls back to
the default. Rejected: `0`, negatives, floats, non-numeric strings,
arrays.

## Two same-input encrypts return the same hex string

That should never happen — `random_bytes()` for the IV/nonce makes
collisions astronomically unlikely.

**If you do observe it:**

1. Check you're not using a forked PHP build with a broken CSPRNG.
2. Check you're not running on a platform where `random_bytes()` is
   silently using a deterministic fallback (none of the supported
   platforms do this, but obscure embedded targets occasionally do).
3. Confirm with a sanity check:

   ```bash
   php -r 'for ($i=0;$i<5;$i++) echo bin2hex(random_bytes(16)), "\n";'
   ```

   Five different lines? Your CSPRNG is fine; the issue is somewhere
   else.

## Performance is slower than expected

Profile before assuming the package is the culprit. Encryption work itself
is microseconds per call; option resolution is even cheaper. Common
real causes:

- **Reconstructing the handler on every call.** Cache the instance
  per-process:

  ```php
  // Bad:
  function encrypt(mixed $v): string {
      return (new Sodium(['key' => getenv('K')]))->encrypt($v);
  }

  // Good:
  function encrypt(mixed $v): string {
      static $handler;
      $handler ??= new Sodium(['key' => getenv('K')]);
      return $handler->encrypt($v);
  }
  ```

- **`getenv()` in the hot path.** It's cheap, but not free. Cache the
  key string too if you're doing this a lot.
- **Switching `algo` to SHA-512 on small payloads.** Doubled HMAC output
  is mostly only visible on multi-megabyte payloads; for cookies, the
  difference is in the noise.

## "It worked on 8.2, fails on 8.5 (or vice versa)"

Should not happen — the CI matrix runs the suite on 8.2, 8.3, 8.4, 8.5 and 8.6.
If you have a reproducer, please [open an issue](https://github.com/InitPHP/Encryption/issues/new)
with the PHP version, the ciphertext bytes, and your handler
construction.

## Still stuck?

- Read [Error Handling](Error-Handling.md) for the canonical message
  catalogue.
- Search [existing issues](https://github.com/InitPHP/Encryption/issues?q=is%3Aissue)
  to see if someone has seen the same thing.
- Ask in [Discussions → Q&A](https://github.com/orgs/InitPHP/discussions/categories/q-a).
- For suspected vulnerabilities, **do not** open a public issue — see
  [`SECURITY.md`](https://github.com/InitPHP/.github/blob/main/SECURITY.md).
