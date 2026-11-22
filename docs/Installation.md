# Installation

`initphp/encryption` is distributed via [Packagist](https://packagist.org/packages/initphp/encryption).
It has no required Composer dependencies — just one of two stock PHP
extensions.

## Requirements

| Requirement | Why |
| --- | --- |
| **PHP `^8.2`** | The package uses `readonly`-friendly patterns, `mixed`, `static` return types and `enum`-flavoured `match` expressions. |
| **`ext-openssl`** (optional) | Required only if you instantiate the [OpenSSL handler](OpenSSL-Handler.md). Ships with mainstream PHP distributions. |
| **`ext-sodium`** (optional) | Required only if you instantiate the [Sodium handler](Sodium-Handler.md). In PHP core since 7.2. |

You only need the extension for the handler you actually use. The package
will not blow up at install time if one of them is missing; it raises
`EncryptionException` only when you try to construct a handler whose
extension isn't loaded.

## Install

```bash
composer require initphp/encryption
```

The package follows [semver](https://semver.org/). The current major is 2.x;
see [Migration from 1.x](Migration-from-1.x.md) before upgrading from a 1.x
install.

## Verify the Install

Drop this script into the root of your project as `check-encryption.php`:

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Sodium;
use InitPHP\Encryption\Exceptions\EncryptionException;

foreach ([OpenSSL::class, Sodium::class] as $class) {
    try {
        $handler = new $class(['key' => 'self-test-key']);
    } catch (EncryptionException $e) {
        echo "[skip]    {$class}: {$e->getMessage()}\n";
        continue;
    }

    $payload    = ['hello' => 'world', 'ts' => time()];
    $ciphertext = $handler->encrypt($payload);
    $roundtrip  = $handler->decrypt($ciphertext);

    if ($roundtrip === $payload) {
        echo "[ok]      {$class}: round-trip succeeded (" . strlen($ciphertext) . " hex chars)\n";
    } else {
        echo "[FAIL]    {$class}: round-trip mismatch\n";
        exit(1);
    }
}

echo "Encryption package is working.\n";
```

Run it:

```bash
php check-encryption.php
```

Expected output (line lengths vary):

```
[ok]      InitPHP\Encryption\OpenSSL: round-trip succeeded (140 hex chars)
[ok]      InitPHP\Encryption\Sodium: round-trip succeeded (148 hex chars)
Encryption package is working.
```

If one of the handlers reports `[skip]`, the corresponding extension is not
loaded in your PHP build. Install it (or fall back to the other handler) —
see [Troubleshooting](Troubleshooting.md) for distribution-specific tips.

## Composer Quality Scripts (for contributors)

If you cloned the repo to contribute, `composer install` also pulls a small
set of development tools. The repo's `composer.json` exposes them as
scripts:

```bash
composer test         # PHPUnit suite
composer phpstan      # PHPStan level 8
composer cs-check     # PER-CS style check (read-only)
composer cs-fix       # PER-CS style fix in place
composer qa           # runs cs-check, phpstan and test in sequence
```

All three gates run on CI for every PR — see
[`CONTRIBUTING.md`](https://github.com/InitPHP/Encryption/blob/main/CONTRIBUTING.md)
for the full contribution flow.

## What Composer Installs

The package itself is tiny — six PHP files in `src/`, no runtime
dependencies:

```
vendor/
└── initphp/
    └── encryption/
        ├── src/
        │   ├── BaseHandler.php
        │   ├── Encrypt.php
        │   ├── HandlerInterface.php
        │   ├── OpenSSL.php
        │   ├── Sodium.php
        │   └── Exceptions/
        │       └── EncryptionException.php
        ├── composer.json
        ├── LICENSE
        └── README.md
```

The dev tooling (`phpunit`, `phpstan`, `php-cs-fixer`) is **`require-dev`
only** — Composer skips it for production installs unless you pass
`--dev`.

## Next Steps

- [Quick Start](Quick-Start.md) — your first encrypt and decrypt
- [Configuration Options](Configuration-Options.md) — every option, every
  default
- [Security Best Practices](Security-Best-Practices.md) — how to generate and
  store a real key
