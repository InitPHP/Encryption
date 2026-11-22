# Quick Start

Five minutes from `composer require` to a working encrypt/decrypt
round-trip.

## 1. Pick a Handler

| You want… | Use |
| --- | --- |
| Modern AEAD, no knobs, fast everywhere | [Sodium](Sodium-Handler.md) |
| Custom AES cipher, FIPS-compatible primitives | [OpenSSL](OpenSSL-Handler.md) |

If unsure, pick **Sodium**. The rest of this page uses it; everything below
works the same with the `OpenSSL` class name swapped in.

## 2. Encrypt and Decrypt

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, [
    'key' => 'replace-me-with-a-real-secret',
]);

// encrypt() accepts mixed; JSON-encodes the payload behind the scenes
$ciphertext = $handler->encrypt([
    'user_id' => 42,
    'roles'   => ['admin', 'editor'],
]);

echo $ciphertext, PHP_EOL;
// Example output (the bytes change every run):
// 020087a3ff...lots of hex...

// decrypt() returns the original PHP value
$payload = $handler->decrypt($ciphertext);
var_export($payload);
// → array (
//     'user_id' => 42,
//     'roles' =>
//     array (
//       0 => 'admin',
//       1 => 'editor',
//     ),
//   )
```

Two things to notice:

1. **The ciphertext starts with `02`.** That's the format version byte. A
   future major release that changes the wire format will bump it and reject
   older ciphertexts with a clear error instead of returning garbage.
2. **You got the original array back, not a serialised blob.** The handler
   records the serialiser choice (JSON or PHP serialize) in the ciphertext
   header, so `decrypt()` always restores the original type. See
   [Serialization](Serialization.md).

## 3. Use the Same Handler for OpenSSL

Identical API; different primitive underneath:

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\OpenSSL;

$handler = Encrypt::use(OpenSSL::class, [
    'key' => 'replace-me-with-a-real-secret',
    // Optional: defaults are sensible.
    // 'cipher' => 'AES-256-CTR',
    // 'algo'   => 'SHA256',
]);

$ciphertext = $handler->encrypt('hello world');
echo $handler->decrypt($ciphertext); // → hello world
```

Both classes implement `HandlerInterface`, so you can write code that takes
either:

```php
use InitPHP\Encryption\HandlerInterface;

function encryptSession(HandlerInterface $handler, array $data): string
{
    return $handler->encrypt($data);
}
```

## 4. Store the Key Out of Source Control

Never put the key in your repo. The recommended pattern:

```php
$key = getenv('APP_ENCRYPTION_KEY')
    ?: throw new RuntimeException('APP_ENCRYPTION_KEY is not set');

$handler = Encrypt::use(\InitPHP\Encryption\Sodium::class, ['key' => $key]);
```

Generate a strong key once, then put it in your secret store / `.env`:

```bash
php -r 'echo bin2hex(random_bytes(32)), "\n";'
# → 64 hex characters; copy into APP_ENCRYPTION_KEY
```

See [Security Best Practices](Security-Best-Practices.md) for storage,
rotation, and compromise response.

## 5. Handle Errors With a Single Catch

Every failure raises `EncryptionException`. One `try` / `catch` covers
malformed input, tampered ciphertexts, missing configuration, and primitive
failures.

```php
use InitPHP\Encryption\Exceptions\EncryptionException;

try {
    $payload = $handler->decrypt($whateverCameInOverTheWire);
} catch (EncryptionException $e) {
    // Don't echo $e->getMessage() to the user — log it server-side instead.
    error_log('decrypt failed: ' . $e->getMessage());
    http_response_code(400);
    exit('Invalid request');
}
```

See [Error Handling](Error-Handling.md) for the full catalogue of messages.

## Common Patterns

### Different options on the same handler per call

Per-call options merge on top of the handler's persistent options and **do
not** mutate the handler:

```php
$handler = new \InitPHP\Encryption\OpenSSL([
    'key'    => 'k',
    'cipher' => 'AES-256-CTR',
]);

$ct = $handler->encrypt('hi', ['cipher' => 'AES-128-CTR']);
echo $handler->getOption('cipher'); // still "AES-256-CTR"

// Decrypt has to use the same per-call cipher:
$handler->decrypt($ct, ['cipher' => 'AES-128-CTR']);
```

### Fluent option setting

`setOption()` and `setOptions()` return the concrete handler type (`static`
covariance), so you can chain:

```php
use InitPHP\Encryption\OpenSSL;

$ct = (new OpenSSL(['key' => 'k']))
    ->setOption('cipher', 'AES-256-CBC')
    ->setOption('algo', 'SHA512')
    ->encrypt(['hello']);
```

### Round-trip a single string

```php
use InitPHP\Encryption\Sodium;

$h = new Sodium(['key' => 'k']);
echo $h->decrypt($h->encrypt('hello')); // → hello
```

## Next Steps

- [Configuration Options](Configuration-Options.md) — full reference
- [Sodium Handler](Sodium-Handler.md) / [OpenSSL Handler](OpenSSL-Handler.md) —
  what each handler does under the hood
- [Recipes](Recipes.md) — cookbook for cookies, DB columns, API tokens, files
- [Security Best Practices](Security-Best-Practices.md) — key management and
  threat model
