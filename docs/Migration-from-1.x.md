# Migration from 1.x

`initphp/encryption` 2.0 is a deliberate hard reset. It tightens the
type system, derives keys to the right length automatically, defaults to
a safer payload serializer, and adopts a self-describing ciphertext
format that rejects ambiguous input.

The cost: **ciphertexts produced by 1.x cannot be decrypted by 2.x.** You
need a re-encryption plan before you upgrade.

## TL;DR

1. Bump PHP to **8.2+** everywhere (CI, dev, production).
2. Add 1.x and 2.x side-by-side temporarily so you can decrypt with 1.x
   and re-encrypt with 2.x. See
   [Re-encryption pattern](#re-encryption-pattern).
3. Replace `Encrypt::create(...)` with `Encrypt::use(...)`.
4. Decide whether your stored payloads should switch to JSON
   (recommended) or keep using PHP serialize. The new option is
   `'serializer' => 'php_serialize'` if you want the old behaviour.
5. Stop pre-deriving 32-byte Sodium keys — pass any non-empty string and
   let the package derive.
6. Drop `ext-mbstring` from your runtime requires if it was only there
   for this package.

## What Changed

### Minimum PHP version

| | 1.x | 2.x |
| --- | --- | --- |
| PHP | `>=7.4` | `^8.1` in 2.x; `^8.2` from 3.0.0 |

The 2.x source uses `mixed`, `static` return types and `match`. The 2.0.0
release required PHP 8.1; version 3.0.0 requires PHP 8.2 (see the
[changelog](https://github.com/InitPHP/Encryption/blob/main/CHANGELOG.md)).

### Ciphertext format

1.x ciphertexts had no version byte: bytes were `HMAC || IV || ciphertext`
(OpenSSL) or `nonce || box` (Sodium). 2.x prepends a 2-byte header
(`VERSION || SERIALIZER_FLAG`).

A 2.x handler asked to decrypt a 1.x ciphertext will throw:

```
EncryptionException: Unsupported ciphertext format version 0x..; expected 0x02.
Ciphertexts produced by 1.x are not readable by 2.x.
```

There is no auto-upgrade path — re-encrypt your data (see below) before
switching handlers.

### Default payload serializer

| | 1.x | 2.x |
| --- | --- | --- |
| Default | `serialize()` / `unserialize()` | JSON |
| Why | Backwards-compat with PHP's native shapes. | `unserialize()` of attacker-controlled bytes is the canonical PHP object-injection vector. JSON cannot instantiate classes. |
| Opt-in to old behaviour | n/a | `'serializer' => 'php_serialize'` |

If your payloads are scalars, arrays, or `stdClass` graphs, JSON is fine.
If they contain raw binary blobs or you really need PHP serialization
semantics, switch the option back.

### Key length for Sodium

In 1.x, the Sodium handler silently broke if the user key wasn't exactly
32 bytes — the README example (`'key' => 'TOP_Secret_Key'`, 14 bytes)
actually couldn't run.

In 2.x, the handler derives a 32-byte key from any non-empty input via
`sodium_crypto_generichash`. **If you were pre-deriving a 32-byte key in
your application code, stop** — let the package do the derivation. If you
keep your own derivation and the result differs from BLAKE2b of your old
input, your ciphertexts won't decrypt cleanly across the upgrade.

### Removed API

- **`Encrypt::create()`** was an alias for `Encrypt::use()`. Use
  `Encrypt::use()` instead.
- **`ext-mbstring` requirement** is gone. The package no longer uses any
  mbstring function. Drop it from your requires if you depended on it
  only for this package.

### Tightened API

- `OpenSSL` and `Sodium` are now `final`. If you were subclassing them,
  switch to extending `BaseHandler` — see
  [Custom Handlers](Custom-Handlers.md).
- `decrypt()` declares `mixed` return type. Consumers typehinted
  `: string` will start to fail.
- `EncryptionException` now extends `\RuntimeException` (was
  `\Exception`). Every existing `catch (Exception $e)` and `catch
  (EncryptionException $e)` continues to work.
- `HandlerInterface` is narrower: `encrypt()`, `decrypt()`,
  `setOptions()` with `mixed` / `string` / `static` signatures. If you
  implemented the interface yourself, update the signatures.

### New API

- `Encrypt::use()` accepts a typed `string|HandlerInterface` parameter
  (was previously documented but not enforced).
- `BaseHandler::SERIALIZER_JSON` and `BaseHandler::SERIALIZER_PHP`
  constants for setting the serializer option without string literals.
- `BaseHandler::FORMAT_VERSION` constant (currently `0x02`) — useful when
  writing tests against the wire format.
- `BaseHandler::setOptions()` and `setOption()` return `static`, so
  fluent chains preserve the concrete handler type.
- Every error message identifies what specifically went wrong; the 1.x
  message was uniformly `"Decryption failed!"`.

## Re-encryption Pattern

The minimal-disruption recipe:

```php
// composer.json: temporarily depend on both versions during the
// migration window. The simplest approach is to vendor the 1.x source
// into your App\Legacy\Crypto namespace and delete it once migration
// completes.

use App\Legacy\Crypto\OpenSSL as LegacyOpenSSL;   // 1.x copy
use InitPHP\Encryption\OpenSSL;                   // 2.x

$legacy = new LegacyOpenSSL([
    'key' => getenv('APP_ENCRYPTION_KEY'),
    // ... whatever options 1.x was using
]);

$new = new OpenSSL([
    'key'        => getenv('APP_ENCRYPTION_KEY'),
    'serializer' => 'php_serialize',  // keep old serializer until
                                       // payloads are converted too
]);

// Background migration job (batch as appropriate):
foreach (legacyCiphertextRows() as $row) {
    try {
        $plaintext = $legacy->decrypt($row->ciphertext);
    } catch (\Throwable $e) {
        // 1.x didn't have version bytes; a successful decrypt is the
        // strongest evidence the row is in fact 1.x.
        logger()->warning('legacy decrypt failed', [
            'id'  => $row->id,
            'msg' => $e->getMessage(),
        ]);
        continue;
    }
    $row->ciphertext = $new->encrypt($plaintext);
    $row->save();
}
```

When every row has been re-encrypted: remove the legacy import, remove
the vendored 1.x source, delete the migration job, and drop the dual-key
fallback from your runtime path.

## "I can't re-encrypt — migration is off the table"

Then either:

- **Stay on 1.x.** It still works on its supported PHP range. No forced
  upgrade.
- **Pin 1.x indefinitely** in `composer.json` (`"initphp/encryption":
  "^1.0"`) and accept that security fixes will only land in 2.x.

Per the [org-wide security policy](https://github.com/InitPHP/.github/blob/main/SECURITY.md),
only the latest stable major receives security fixes. Once 2.0 ships,
1.x is end-of-life.

## Pre-deploy Checklist

- [ ] CI passes on PHP 8.2+ (drop older PHP from the matrix).
- [ ] All `Encrypt::create(...)` calls replaced with `Encrypt::use(...)`.
- [ ] No code extends `OpenSSL` or `Sodium` directly (extend
      `BaseHandler` instead).
- [ ] `decrypt()` callers handle `mixed` (or you cast in one place).
- [ ] Re-encryption job has finished, **or** you have an explicit
      dual-stack decrypt path with a `try` / `catch (EncryptionException)`
      fallback.
- [ ] You decided whether to switch to `'serializer' => 'json'` or pin
      `'serializer' => 'php_serialize'`.
- [ ] `ext-mbstring` removed from your require list if you don't need
      it elsewhere.

## See Also

- [Installation](Installation.md) — install 2.x once you're ready.
- [Quick Start](Quick-Start.md) — to see the new defaults in action.
- [Configuration Options](Configuration-Options.md) — the new option
  surface.
- [Security Best Practices](Security-Best-Practices.md) — why
  `unserialize()` on attacker bytes used to be the worry and is no
  longer the default.
- [`CHANGELOG.md`](https://github.com/InitPHP/Encryption/blob/main/CHANGELOG.md) —
  the canonical changelog.
