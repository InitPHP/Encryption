# Migrating from 1.x to 2.x

`initphp/encryption` 2.0 is a deliberate hard reset. It tightens the type
system, derives keys to the right length automatically, defaults to a safer
serializer, and adopts a self-describing ciphertext format that rejects
ambiguous input.

The cost: **ciphertexts produced by 1.x cannot be decrypted by 2.x.** You
need a re-encryption plan before you upgrade.

This page is the full checklist.

## TL;DR

1. Bump PHP to **8.1+** in your CI and production environments.
2. Add 1.x and 2.x side by side temporarily so you can decrypt with 1.x and
   re-encrypt with 2.x (see [Re-encryption pattern](#re-encryption-pattern)).
3. Replace `Encrypt::create(...)` with `Encrypt::use(...)`.
4. Decide whether your stored payloads should switch to JSON (recommended)
   or keep using `serialize`/`unserialize`. The new option is
   `'serializer' => 'php_serialize'` if you keep the old behaviour.
5. Remove the old, manually-derived 32-byte key dance for Sodium — pass any
   non-empty key now.
6. Drop `ext-mbstring` from your runtime requirements if you only required
   it for this package.

## What Changed

### Minimum PHP version

| | 1.x | 2.x |
| --- | --- | --- |
| PHP | `>= 7.4` | `^8.1` |

The 2.x source uses `mixed`, `static` return types, `enum` (via match), and
readonly-friendly patterns that require PHP 8.1.

### Ciphertext format

1.x ciphertexts had no version byte: the first bytes were the HMAC (for
OpenSSL) or the nonce (for Sodium), followed directly by the encrypted
payload. 2.x prepends a 2-byte header (`VERSION || SERIALIZER_FLAG`).

Concretely, this means **a 2.x handler asked to decrypt a 1.x ciphertext
will throw**:

```text
EncryptionException: Unsupported ciphertext format version 0x..; expected 0x02.
Ciphertexts produced by 1.x are not readable by 2.x.
```

There is no auto-upgrade path. Re-encrypt your data (see below) before
flipping the handler classes.

### Default payload serializer

| | 1.x | 2.x |
| --- | --- | --- |
| Default | `serialize()` / `unserialize()` | JSON |
| Why | Backwards-compatible with PHP's native shapes. | `unserialize()` of attacker-controlled bytes is the canonical PHP object-injection vector. JSON cannot instantiate classes. |
| Opt-in to old behaviour | n/a | `'serializer' => 'php_serialize'` |

If your payloads are scalars, arrays, or plain objects (`stdClass` /
deeply-mapped DTOs), JSON is fine and is the recommended target. If they
contain raw binary blobs (e.g. `random_bytes()` output), JSON is not
8-bit-clean — keep `php_serialize`.

### Key length for Sodium

1.x silently broke if the user key wasn't exactly 32 bytes long. The README
example (`'key' => 'TOP_Secret_Key'`, 14 bytes) actually couldn't run.

2.x derives a 32-byte key from any non-empty input via
`sodium_crypto_generichash`. Any key string you can pass in now Just Works.

If your application was working around this by passing a pre-derived
32-byte key, **stop doing that** — let the package do the derivation. If you
keep doing your own derivation and the result differs from BLAKE2b of your
old key, your ciphertexts won't decrypt cleanly across the upgrade.

### Removed API

- **`Encrypt::create()`** — was an alias for `Encrypt::use()`. Use
  `Encrypt::use()` instead.
- **`ext-mbstring` requirement** — the package no longer uses any mbstring
  function. Drop it from your `require` if it was there only for this
  package.

### Tightened API

- `OpenSSL` and `Sodium` are now `final`. If you were extending them, switch
  to extending `BaseHandler` (see [04 — Custom Handlers](./04-custom-handlers.md)).
- `decrypt()` returns `mixed` instead of an untyped value. Consumers
  typehinted `: string` will start to fail.
- `EncryptionException` extends `\RuntimeException` (was `\Exception`). All
  existing `catch (Exception $e)` and `catch (EncryptionException $e)`
  callsites continue to work.
- The HandlerInterface is now narrower: it requires `encrypt()`, `decrypt()`,
  and `setOptions()` with `mixed` / `string` / `static` types. If you
  implemented the interface yourself, update the signatures.

### New API

- `Encrypt::use()` accepts a typed `string|HandlerInterface` parameter
  (previously documented but not enforced).
- `BaseHandler::SERIALIZER_JSON` and `BaseHandler::SERIALIZER_PHP`
  constants for setting the serializer option without string literals.
- `BaseHandler::FORMAT_VERSION` constant (currently `0x02`) — useful when
  writing tests against the wire format.
- `BaseHandler::setOptions()` and `setOption()` return `static`, so
  fluent chains preserve the concrete handler type.
- New per-handler error messages identifying what specifically went wrong
  (the 1.x message was always `"Decryption failed!"`).

## Re-encryption Pattern

The minimal-disruption recipe:

```php
// composer.json: require BOTH versions, namespaced separately, e.g. via a
// fork like initphp/encryption-v1 (manual setup). In practice most users
// vendor the 1.x source into App\Legacy\Crypto for the migration window
// and delete it afterwards.

use App\Legacy\Crypto\OpenSSL as LegacyOpenSSL;       // 1.x
use InitPHP\Encryption\OpenSSL;                       // 2.x

$legacy = new LegacyOpenSSL([
    'key' => getenv('APP_ENCRYPTION_KEY'),
    // ... whatever options 1.x was using
]);

$new = new OpenSSL([
    'key' => getenv('APP_ENCRYPTION_KEY'),
    // 'serializer' => 'php_serialize',  // ← keep the old serializer
    //                                      until you also convert payloads
]);

// Migration step (background job, batched):
foreach (legacyCiphertextRows() as $row) {
    try {
        $plaintext = $legacy->decrypt($row->ciphertext);
    } catch (\Throwable $e) {
        // 1.x didn't have version bytes; a successful decrypt is the
        // strongest evidence the row is in fact 1.x.
        logger()->warning('legacy decrypt failed', [
            'id' => $row->id,
            'msg' => $e->getMessage(),
        ]);
        continue;
    }
    $newCiphertext = $new->encrypt($plaintext);
    persist($row->id, $newCiphertext);
}
```

When every row has been re-encrypted: remove the legacy import,
`composer remove` the fork, delete the migration job, and drop the dual-key
fallback from your runtime code path.

## "I Can't Re-encrypt — Migration Is Off the Table"

Then either:

- **Stay on 1.x.** It still works on its supported PHP range. There is no
  forced upgrade.
- **Pin 1.x indefinitely** in your `composer.json` (`"initphp/encryption":
  "^1.0"`) and accept that security fixes will only land in 2.x.

Per the [org-wide security policy](../SECURITY.md), only the latest stable
major receives security fixes. Once 2.0 ships, 1.x is end-of-life.

## Quick Checklist Before You Deploy 2.x

- [ ] CI passes on PHP 8.1+ (drop older PHP from your matrix).
- [ ] All `Encrypt::create(...)` calls replaced with `Encrypt::use(...)`.
- [ ] No code extends `OpenSSL` or `Sodium` directly (extend `BaseHandler`).
- [ ] `decrypt()` callers handle `mixed` (or you cast in one place).
- [ ] Re-encryption job has finished, or you have an explicit dual-stack
      decrypt path with a `try` / `catch (EncryptionException)` fallback.
- [ ] You decided whether to switch to `'serializer' => 'json'` or pin
      `'serializer' => 'php_serialize'`.
- [ ] `ext-mbstring` removed from your require list if you don't need it
      elsewhere.

## See Also

- [01 — Getting Started](./01-getting-started.md) — to learn the new
  defaults.
- [05 — Options](./05-options.md) — the full new option surface.
- [07 — Security](./07-security.md) — what `unserialize` on attacker bytes
  used to risk, and why JSON is the new default.
- [`CHANGELOG.md`](../CHANGELOG.md) — the canonical list of changes in 2.0.
