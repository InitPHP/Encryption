# Getting Started

This page takes you from "I just ran `composer require`" to a working
encrypt/decrypt round-trip. Five minutes.

## Install

```bash
composer require initphp/encryption
```

The package itself has no Composer runtime dependencies — it ships handlers
for the two PHP extensions you (probably) already have.

## Pick a Handler

| You want… | Use |
| --- | --- |
| The widest possible compatibility, custom cipher choice, FIPS-friendly primitives | [`OpenSSL`](./02-openssl-handler.md) |
| A modern AEAD with no knobs to mis-set, fast performance | [`Sodium`](./03-sodium-handler.md) |

If you have no opinion, **pick Sodium**. It is harder to misuse and the
defaults are what you want.

Both handlers are interchangeable through the same `HandlerInterface`, so
swapping later is just a constructor change — at the cost of re-encrypting
already-stored data, since the ciphertext formats differ.

## Your First Encrypt / Decrypt

Create `try-encryption.php`:

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, [
    'key' => 'change-me-to-a-real-secret',
]);

$ciphertext = $handler->encrypt(['user_id' => 42, 'email' => 'alice@example.com']);
echo "ciphertext: {$ciphertext}\n";

$plaintext = $handler->decrypt($ciphertext);
echo "plaintext:  " . json_encode($plaintext) . "\n";
```

Run it:

```bash
php try-encryption.php
```

Expected output (the ciphertext bytes vary every run; the structure does not):

```
ciphertext: 020047ae3f8c...long hex string...
plaintext:  {"user_id":42,"email":"alice@example.com"}
```

Two things to notice:

1. The ciphertext starts with `02`. That is the format version byte;
   anything that doesn't start with `02` will be rejected by 2.x with a clear
   error.
2. The plaintext came back as the original array, not a serialized blob.
   The handler tracks the serializer choice in the ciphertext itself, so
   `decrypt()` always returns the original type.

## Where Should the Key Live?

**Not in your source code.** A typical layout:

```php
$key = getenv('APP_ENCRYPTION_KEY')
    ?: throw new RuntimeException('APP_ENCRYPTION_KEY is not set');

$handler = Encrypt::use(\InitPHP\Encryption\Sodium::class, ['key' => $key]);
```

For production, generate a strong key once and store it in your secret
manager / `.env` / Kubernetes Secret / whatever you already use:

```bash
php -r 'echo bin2hex(random_bytes(32)), "\n";'
# → 64 hex characters; treat as you would any other secret
```

See [docs/07-security.md](./07-security.md) for key generation, storage and
rotation patterns.

## Verifying the Install

Run a quick sanity script — useful to drop into CI to confirm both extensions
are available:

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Sodium;

foreach ([OpenSSL::class, Sodium::class] as $class) {
    $handler = new $class(['key' => 'self-test-key']);
    $ct = $handler->encrypt(['hello' => 'world']);
    $pt = $handler->decrypt($ct);
    assert($pt === ['hello' => 'world'], "{$class} round-trip failed");
    echo "{$class} OK\n";
}
```

If either handler is missing its extension you'll get a clear
`EncryptionException` at construction time:

```
The "sodium" extension is required by the Sodium handler.
```

## Next Steps

- Configure the handler for your use case → [05 — Options Reference](./05-options.md)
- Understand the handler you picked →
  [02 — OpenSSL Handler](./02-openssl-handler.md) or
  [03 — Sodium Handler](./03-sodium-handler.md)
- Plan key management → [07 — Security](./07-security.md)
- Know what can fail → [06 — Error Handling](./06-error-handling.md)
